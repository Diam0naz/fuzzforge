//! Raydium CP-Swap (commit 3d69122) × supported-mint matrix.
//!
//! Scope: mint handling and token-transfer assumptions against the program's
//! documented supported token types (SPL Token; Token-2022 with TransferFee,
//! MetadataPointer, TokenMetadata, InterestBearing, ScaledUiAmount).
//!
//! Preflight (once, at setup): unsupported extensions are rejected at pool
//! creation, supported ones are accepted.
//!
//! Fuzzed invariants, per pool, after every action:
//! * solvency: each vault holds at least the protocol + fund + creator fees
//!   the pool has booked against it;
//! * LP share value: sqrt(r0 * r1) / lp_supply never decreases, with reserves
//!   measured from the real vault balances minus booked fees.
//!
//! Instructions are built by hand (no IDL) from the program's Accounts structs.
//!
//!   crucible run -C targets/raydium_cp_swap raydium_cp_swap amm_invariants --release --timeout 300

use crucible_fuzzer::anchor_lang::prelude::Clock;
use crucible_fuzzer::*;
use fuzzforge_scenarios::anchor::{account_discriminator, det_keypair, read_pubkey, read_u64, AnchorIx};
use fuzzforge_scenarios::invariants::summarize_logs;
use fuzzforge_scenarios::token2022::{read_token_account, MintHandle, MintProfile, TokenEnv, SPL_TOKEN_ID, TOKEN_2022_ID};
use fuzzforge_scenarios::ShareValueLedger;
use solana_account::Account;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use std::rc::Rc;

const PROGRAM_ID: Pubkey = Pubkey::from_str_const("CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C");
const CREATE_POOL_FEE: Pubkey = Pubkey::from_str_const("DNXgeM9EiiaAbaWvwjHj9fQQLAX5ZsfHyvmYUNRAdNC8");
const MEMO_V3: Pubkey = Pubkey::from_str_const("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
const ATA_PROGRAM: Pubkey = Pubkey::from_str_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
const SYSVAR_RENT: Pubkey = Pubkey::from_str_const("SysvarRent111111111111111111111111111111111");
const SYSTEM_PROGRAM: Pubkey = Pubkey::from_str_const("11111111111111111111111111111111");

const SOL: u64 = 1_000_000_000;
const USER_TOKENS: u64 = 1_000_000_000_000_000;
const DECIMALS: u8 = 6;
const START_TS: i64 = 1_700_000_000;

// Mainnet-like config: 0.25% trade fee, 12% of it to protocol, 4% to fund.
const TRADE_FEE_RATE: u64 = 2_500;
const PROTOCOL_FEE_RATE: u64 = 120_000;
const FUND_FEE_RATE: u64 = 40_000;
// Creator fee 0.1% of volume on v2 pools; the protocol keeps 20% of it.
const CREATOR_FEE_RATE: u64 = 1_000;
const CREATOR_FEE_SHARE_RATE: u64 = 200_000;

// PoolState is #[repr(C, packed)]; offsets include the 8-byte discriminator.
const OFF_TOKEN_0_VAULT: usize = 8 + 32 * 2;
const OFF_LP_SUPPLY: usize = 333;
const OFF_PROTOCOL_FEES_0: usize = 341;
const OFF_PROTOCOL_FEES_1: usize = 349;
const OFF_FUND_FEES_0: usize = 357;
const OFF_FUND_FEES_1: usize = 365;
const OFF_CREATOR_FEES_0: usize = 397;
const OFF_CREATOR_FEES_1: usize = 405;

use MintProfile::*;
// CreatorFeeOn as encoded by initialize_v2.
const CREATOR_BOTH: Option<u8> = Some(0);
const CREATOR_TOKEN0: Option<u8> = Some(1);
const CREATOR_TOKEN1: Option<u8> = Some(2);

/// (side A profile, side B profile, initial A, initial B, creator fee mode).
/// Sides are sorted into token_0/token_1 by mint address at setup. `None`
/// creates the pool with `initialize`; `Some(mode)` uses `initialize_v2` with
/// the creator fee on.
const POOLS: [(MintProfile, MintProfile, u64, u64, Option<u8>); 9] = [
    (SplToken, SplToken, 1_000_000_000, 1_000_000_000, None),
    (SplToken, TransferFee, 1_000_000_000, 3_000_000_000, None),
    (TransferFee, TransferFeeCapped, 1_000_000, 1_000_000, None),
    (Plain2022, InterestBearing, 1_000_000_000, 1_000_000_000, None),
    (TransferFeeMax, SplToken, 1_000_000_000, 1_000_000_000, None),
    (TransferFee, SplToken, 10_000, 20_000, None),
    (SplToken, TransferFee, 1_000_000_000, 1_000_000_000, CREATOR_BOTH),
    (TransferFeeCapped, SplToken, 1_000_000, 2_000_000, CREATOR_TOKEN0),
    (TransferFee, TransferFeeMax, 50_000_000, 50_000_000, CREATOR_TOKEN1),
];
const NP: usize = POOLS.len();
const NU: usize = 2;

#[derive(Clone)]
struct Pool {
    label: String,
    m0: MintHandle,
    m1: MintHandle,
    state: Pubkey,
    authority: Pubkey,
    lp_mint: Pubkey,
    vault0: Pubkey,
    vault1: Pubkey,
    observation: Pubkey,
    user_t0: [Pubkey; NU],
    user_t1: [Pubkey; NU],
    user_lp: [Pubkey; NU],
    live: bool,
    creator_fee: bool,
    share: ShareValueLedger,
}

#[derive(Clone, Copy, Debug)]
struct PoolView {
    vault0: u64,
    vault1: u64,
    fees0: u64,
    fees1: u64,
    lp_supply: u64,
}

#[derive(Clone)]
struct AmmFixture {
    ctx: TestContext,
    users: [Rc<Keypair>; NU],
    amm_config: Pubkey,
    pools: Vec<Pool>,
    mint_authority: Rc<Keypair>,
    issuer: Rc<Keypair>,
    /// Violations recorded inside actions (exact-accounting checks).
    accounting: Vec<String>,
}

fn pda(seeds: &[&[u8]]) -> Pubkey {
    Pubkey::find_program_address(seeds, &PROGRAM_ID).0
}

fn send(ctx: &mut TestContext, ix: solana_instruction_shim::Instruction, signer: &Keypair) -> Result<(), String> {
    match ctx.raw_call(ix).signers(&[signer]).send() {
        Ok(o) if o.is_success() => Ok(()),
        Ok(o) => {
            if std::env::var("FF_DEBUG_LOGS").is_ok() {
                eprintln!("[FF_DEBUG] {}", o.logs().join("\n[FF_DEBUG] "));
            }
            Err(summarize_logs(o.logs()))
        }
        Err(e) => Err(e.to_string()),
    }
}

// raw_call takes the instruction type re-exported through anchor-lang.
mod solana_instruction_shim {
    pub use crucible_fuzzer::anchor_lang::solana_program::instruction::Instruction;
}

fn write_amm_config(ctx: &mut TestContext, address: Pubkey) {
    let mut d = account_discriminator("AmmConfig").to_vec();
    d.push(0); // bump
    d.push(0); // disable_create_pool
    d.extend_from_slice(&0u16.to_le_bytes()); // index
    for v in [TRADE_FEE_RATE, PROTOCOL_FEE_RATE, FUND_FEE_RATE, 0 /* create_pool_fee */] {
        d.extend_from_slice(&v.to_le_bytes());
    }
    d.extend_from_slice(Pubkey::new_unique().as_ref()); // protocol_owner
    d.extend_from_slice(Pubkey::new_unique().as_ref()); // fund_owner
    d.extend_from_slice(&CREATOR_FEE_RATE.to_le_bytes());
    d.extend_from_slice(&CREATOR_FEE_SHARE_RATE.to_le_bytes());
    d.extend_from_slice(&[0u8; 8 * 14]); // padding
    assert_eq!(d.len(), 236, "AmmConfig::LEN");
    ctx.write_account(&address, Account { lamports: 10 * SOL, data: d, owner: PROGRAM_ID, executable: false, rent_epoch: 0 })
        .unwrap();
}

fn advance_epoch(ctx: &mut TestContext) {
    let mut clock: Clock = ctx.svm.get_sysvar::<Clock>();
    clock.epoch += 1;
    clock.slot += 432_000;
    clock.unix_timestamp += 2 * 86_400;
    ctx.set_sysvar(&clock);
}

fn set_time(ctx: &mut TestContext, ts: i64) {
    let mut clock: Clock = ctx.svm.get_sysvar::<Clock>();
    clock.unix_timestamp = ts;
    ctx.set_sysvar(&clock);
}

impl AmmFixture {
    fn view(&self, p: usize) -> Option<PoolView> {
        let pool = &self.pools[p];
        let acc = self.ctx.svm.get_account(&pool.state)?;
        let d = &acc.data;
        if d.len() < OFF_CREATOR_FEES_1 + 8 {
            return None;
        }
        Some(PoolView {
            vault0: read_token_account(&self.ctx, &pool.vault0).amount,
            vault1: read_token_account(&self.ctx, &pool.vault1).amount,
            fees0: read_u64(d, OFF_PROTOCOL_FEES_0) + read_u64(d, OFF_FUND_FEES_0) + read_u64(d, OFF_CREATOR_FEES_0),
            fees1: read_u64(d, OFF_PROTOCOL_FEES_1) + read_u64(d, OFF_FUND_FEES_1) + read_u64(d, OFF_CREATOR_FEES_1),
            lp_supply: read_u64(d, OFF_LP_SUPPLY),
        })
    }

    fn initialize_ix(&self, creator: &Keypair, m0: &MintHandle, m1: &MintHandle, a0: u64, a1: u64, creator_fee_on: Option<u8>) -> (solana_instruction_shim::Instruction, Pool) {
        let state = pda(&[b"pool", self.amm_config.as_ref(), m0.mint.as_ref(), m1.mint.as_ref()]);
        let authority = pda(&[b"vault_and_lp_mint_auth_seed"]);
        let lp_mint = pda(&[b"pool_lp_mint", state.as_ref()]);
        let vault0 = pda(&[b"pool_vault", state.as_ref(), m0.mint.as_ref()]);
        let vault1 = pda(&[b"pool_vault", state.as_ref(), m1.mint.as_ref()]);
        let observation = pda(&[b"observation", state.as_ref()]);
        let lp_handle = MintHandle { profile: SplToken, mint: lp_mint, token_program: SPL_TOKEN_ID, decimals: 9 };
        let creator_lp = lp_handle.ata(&creator.pubkey());
        let b = match creator_fee_on {
            None => AnchorIx::new(PROGRAM_ID, "initialize").u64(a0).u64(a1).u64(0),
            Some(mode) => AnchorIx::new(PROGRAM_ID, "initialize_v2").u64(a0).u64(a1).u64(0).option_tag(true).u8(mode),
        };
        let b = b
            .signer_mut(creator.pubkey())
            .readonly(self.amm_config)
            .readonly(authority)
            .mutable(state)
            .readonly(m0.mint)
            .readonly(m1.mint)
            .mutable(lp_mint)
            .mutable(m0.ata(&creator.pubkey()))
            .mutable(m1.ata(&creator.pubkey()))
            .mutable(creator_lp)
            .mutable(vault0)
            .mutable(vault1)
            .mutable(CREATE_POOL_FEE)
            .mutable(observation)
            .readonly(SPL_TOKEN_ID)
            .readonly(m0.token_program)
            .readonly(m1.token_program)
            .readonly(ATA_PROGRAM)
            .readonly(SYSTEM_PROGRAM);
        // initialize_v2 drops the unused rent sysvar.
        let ix = if creator_fee_on.is_none() { b.readonly(SYSVAR_RENT).build() } else { b.build() };
        let pool = Pool {
            label: String::new(),
            m0: m0.clone(),
            m1: m1.clone(),
            state,
            authority,
            lp_mint,
            vault0,
            vault1,
            observation,
            user_t0: Default::default(),
            user_t1: Default::default(),
            user_lp: Default::default(),
            live: false,
            creator_fee: creator_fee_on.is_some(),
            share: Default::default(),
        };
        (ix, pool)
    }

    fn deposit_or_withdraw(&mut self, p: usize, u: usize, lp: u64, deposit: bool) -> Result<(), String> {
        let pool = &self.pools[p];
        let user = self.users[u].clone();
        let mut b = if deposit {
            AnchorIx::new(PROGRAM_ID, "deposit").u64(lp).u64(u64::MAX).u64(u64::MAX)
        } else {
            AnchorIx::new(PROGRAM_ID, "withdraw").u64(lp).u64(0).u64(0)
        };
        b = b
            .signer(user.pubkey())
            .readonly(pool.authority)
            .mutable(pool.state)
            .mutable(pool.user_lp[u])
            .mutable(pool.user_t0[u])
            .mutable(pool.user_t1[u])
            .mutable(pool.vault0)
            .mutable(pool.vault1)
            .readonly(SPL_TOKEN_ID)
            .readonly(TOKEN_2022_ID)
            .readonly(pool.m0.mint)
            .readonly(pool.m1.mint)
            .mutable(pool.lp_mint);
        if !deposit {
            b = b.readonly(MEMO_V3);
        }
        send(&mut self.ctx, b.build(), &user)
    }

    fn swap(&mut self, p: usize, u: usize, zero_for_one: bool, base_input: bool, amount: u64) -> Result<(), String> {
        let pool = &self.pools[p];
        let user = self.users[u].clone();
        let (in_m, out_m, in_v, out_v, in_a, out_a) = if zero_for_one {
            (&pool.m0, &pool.m1, pool.vault0, pool.vault1, pool.user_t0[u], pool.user_t1[u])
        } else {
            (&pool.m1, &pool.m0, pool.vault1, pool.vault0, pool.user_t1[u], pool.user_t0[u])
        };
        let b = if base_input {
            AnchorIx::new(PROGRAM_ID, "swap_base_input").u64(amount).u64(0)
        } else {
            AnchorIx::new(PROGRAM_ID, "swap_base_output").u64(u64::MAX).u64(amount)
        };
        let ix = b
            .signer(user.pubkey())
            .readonly(pool.authority)
            .readonly(self.amm_config)
            .mutable(pool.state)
            .mutable(in_a)
            .mutable(out_a)
            .mutable(in_v)
            .mutable(out_v)
            .readonly(in_m.token_program)
            .readonly(out_m.token_program)
            .readonly(in_m.mint)
            .readonly(out_m.mint)
            .mutable(pool.observation)
            .build();
        send(&mut self.ctx, ix, &user)
    }

    /// Fuzzer amount: either a dust-sized absolute amount (rounding edges) or
    /// parts-per-million of a reference quantity (economically sized moves).
    fn scaled(reference: u64, ppm: u64, dust: bool) -> u64 {
        if dust {
            ppm % 10_000 + 1
        } else {
            ((reference as u128 * ppm as u128) / 1_000_000).max(1) as u64
        }
    }
}

#[fuzz_fixture]
impl AmmFixture {
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();
        let so = std::env::var("FF_PROGRAM_SO").unwrap_or_else(|_| "program/raydium_cp_swap.so".into());
        ctx.add_program(&PROGRAM_ID, &so).expect("load raydium_cp_swap.so");
        set_time(&mut ctx, START_TS);

        let users = [Rc::new(det_keypair("user-0")), Rc::new(det_keypair("user-1"))];
        let mint_authority = det_keypair("mint-authority");
        let issuer = det_keypair("issuer");
        for kp in users.iter().map(|u| &**u).chain([&mint_authority, &issuer]) {
            ctx.create_account().pubkey(kp.pubkey()).lamports(1_000 * SOL).owner(SYSTEM_PROGRAM).create().unwrap();
        }

        let amm_config = det_keypair("amm-config").pubkey();
        write_amm_config(&mut ctx, amm_config);
        let mint_authority = Rc::new(mint_authority);
        let issuer = Rc::new(issuer);
        let mut f = Self {
            ctx,
            users,
            amm_config,
            pools: Vec::new(),
            mint_authority: mint_authority.clone(),
            issuer: issuer.clone(),
            accounting: Vec::new(),
        };

        let env = TokenEnv { payer: &f.users[0], mint_authority: &mint_authority, attacker: &issuer };

        // Fee receiver at its hard-coded address; only touched when create_pool_fee != 0.
        let fee_mint = env.create_mint(&mut f.ctx, SplToken, &det_keypair("fee-mint"), 9).unwrap();
        f.ctx.create_token_account().pubkey(CREATE_POOL_FEE).mint(fee_mint.mint).token_owner(Pubkey::new_unique()).create().unwrap();

        // ---- Preflight: mint support policy ----------------------------------
        let policy: [(MintProfile, bool); 7] = [
            (TransferFee, true),
            (TransferFeeCapped, true),
            (TransferFeeMax, true),
            (InterestBearing, true),
            (PermanentDelegate, false),
            (TransferHook, false),
            (NonTransferable, false),
        ];
        for (i, (profile, expect_ok)) in policy.into_iter().enumerate() {
            let mut probe = f.clone();
            let env = TokenEnv { payer: &probe.users[0].clone(), mint_authority: &mint_authority, attacker: &issuer };
            let x = env.create_mint(&mut probe.ctx, profile, &det_keypair(&format!("pf-x-{i}")), DECIMALS).unwrap();
            let y = env.create_mint(&mut probe.ctx, SplToken, &det_keypair(&format!("pf-y-{i}")), DECIMALS).unwrap();
            let (m0, m1) = if x.mint < y.mint { (x, y) } else { (y, x) };
            let creator = probe.users[0].clone();
            env.fund(&mut probe.ctx, &m0, &creator.pubkey(), USER_TOKENS).unwrap();
            env.fund(&mut probe.ctx, &m1, &creator.pubkey(), USER_TOKENS).unwrap();
            let (ix, _) = probe.initialize_ix(&creator, &m0, &m1, 1_000_000_000, 1_000_000_000, None);
            let r = send(&mut probe.ctx, ix, &creator);
            let verdict = match (r.is_ok(), expect_ok) {
                (true, true) => "accepted (supported, as documented)".to_string(),
                (false, false) => "rejected (unsupported, as documented)".to_string(),
                (true, false) => "ACCEPTED but documented as unsupported".to_string(),
                (false, true) => format!("REJECTED but documented as supported: {}", r.unwrap_err()),
            };
            println!("[FF_PREFLIGHT] [mint-policy] {}: {verdict}", profile.name());
        }

        // ---- Pools under test ------------------------------------------------
        for (p, (pa, pb, ia, ib, creator_fee_on)) in POOLS.into_iter().enumerate() {
            let env = TokenEnv { payer: &f.users[0].clone(), mint_authority: &mint_authority, attacker: &issuer };
            let a = env.create_mint(&mut f.ctx, pa, &det_keypair(&format!("pool-{p}-a")), DECIMALS).unwrap();
            let b = env.create_mint(&mut f.ctx, pb, &det_keypair(&format!("pool-{p}-b")), DECIMALS).unwrap();
            let ((m0, i0), (m1, i1)) = if a.mint < b.mint { ((a, ia), (b, ib)) } else { ((b, ib), (a, ia)) };
            let mut user_t0 = [Pubkey::default(); NU];
            let mut user_t1 = [Pubkey::default(); NU];
            for u in 0..NU {
                let owner = f.users[u].pubkey();
                user_t0[u] = env.fund(&mut f.ctx, &m0, &owner, USER_TOKENS).unwrap();
                user_t1[u] = env.fund(&mut f.ctx, &m1, &owner, USER_TOKENS).unwrap();
            }
            let creator = f.users[0].clone();
            let (ix, mut pool) = f.initialize_ix(&creator, &m0, &m1, i0, i1, creator_fee_on);
            let mode = match creator_fee_on {
                None => String::new(),
                Some(m) => format!(", creator fee on {}", ["both", "token0", "token1"][m as usize]),
            };
            pool.label = format!("pool{p}[{} / {}{mode}]", m0.profile.name(), m1.profile.name());
            pool.user_t0 = user_t0;
            pool.user_t1 = user_t1;
            match send(&mut f.ctx, ix, &creator) {
                Ok(()) => {
                    pool.live = true;
                    let lp_handle = MintHandle { profile: SplToken, mint: pool.lp_mint, token_program: SPL_TOKEN_ID, decimals: 9 };
                    for u in 0..NU {
                        pool.user_lp[u] = env.fund(&mut f.ctx, &lp_handle, &f.users[u].pubkey(), 0).unwrap();
                    }
                    let d = f.ctx.svm.get_account(&pool.state).unwrap().data;
                    assert_eq!(read_pubkey(&d, OFF_TOKEN_0_VAULT), pool.vault0, "PoolState layout drifted");
                }
                Err(e) => println!("[FF_PREFLIGHT] [setup] {} failed to initialize: {e}", pool.label),
            }
            f.pools.push(pool);
        }

        // Pools open one second after creation.
        set_time(&mut f.ctx, START_TS + 10);
        for p in 0..NP {
            if let Some(v) = f.view(p) {
                let (r0, r1) = (v.vault0.saturating_sub(v.fees0), v.vault1.saturating_sub(v.fees1));
                let label = f.pools[p].label.clone();
                f.pools[p].share.observe(&label, r0, r1, v.lp_supply);
            }
        }
        f
    }

    pub fn action_deposit(&mut self, #[range(0..9)] p: usize, #[range(0..2)] u: usize, #[range(1..2_000_000)] ppm: u64, dust: bool) -> bool {
        let p = p % NP;
        if !self.pools[p].live {
            return false;
        }
        let supply = self.view(p).map_or(0, |v| v.lp_supply);
        let lp = Self::scaled(supply, ppm, dust);
        self.deposit_or_withdraw(p, u % NU, lp, true).is_ok()
    }

    pub fn action_withdraw(&mut self, #[range(0..9)] p: usize, #[range(0..2)] u: usize, #[range(1..1_000_001)] ppm: u64, dust: bool) -> bool {
        let p = p % NP;
        let u = u % NU;
        if !self.pools[p].live {
            return false;
        }
        let bal = read_token_account(&self.ctx, &self.pools[p].user_lp[u]).amount;
        if bal == 0 {
            return false;
        }
        let lp = Self::scaled(bal, ppm, dust).min(bal);
        self.deposit_or_withdraw(p, u, lp, false).is_ok()
    }

    pub fn action_swap_base_input(&mut self, #[range(0..9)] p: usize, #[range(0..2)] u: usize, zero_for_one: bool, #[range(1..2_000_000)] ppm: u64, dust: bool) -> bool {
        let p = p % NP;
        let Some(v) = self.pools[p].live.then(|| self.view(p)).flatten() else { return false };
        let reserve_in = if zero_for_one { v.vault0 } else { v.vault1 };
        let amount = Self::scaled(reserve_in, ppm, dust);
        self.swap(p, u % NU, zero_for_one, true, amount).is_ok()
    }

    pub fn action_swap_base_output(&mut self, #[range(0..9)] p: usize, #[range(0..2)] u: usize, zero_for_one: bool, #[range(1..1_000_000)] ppm: u64, dust: bool) -> bool {
        let p = p % NP;
        let Some(v) = self.pools[p].live.then(|| self.view(p)).flatten() else { return false };
        let reserve_out = if zero_for_one { v.vault1 } else { v.vault0 };
        let amount = Self::scaled(reserve_out, ppm, dust);
        self.swap(p, u % NU, zero_for_one, false, amount).is_ok()
    }

    pub fn action_advance_time(&mut self, #[range(1..86_400)] secs: u64) -> bool {
        let now = self.ctx.svm.get_sysvar::<Clock>().unix_timestamp;
        set_time(&mut self.ctx, now + secs as i64);
        true
    }

    /// Pool creator collects the creator fee. The protocol's share is rebooked
    /// as protocol fees and the rest leaves the vault, so LP reserves
    /// (vault minus booked fees) must not change by a single unit.
    pub fn action_collect_creator_fee(&mut self, #[range(0..9)] p: usize) -> bool {
        let p = p % NP;
        if !self.pools[p].live || !self.pools[p].creator_fee {
            return false;
        }
        let Some(before) = self.view(p) else { return false };
        let pool = &self.pools[p];
        let creator = self.users[0].clone();
        let fee_share = pda(&[b"creator_fee_share", creator.pubkey().as_ref(), self.amm_config.as_ref()]);
        let ix = AnchorIx::new(PROGRAM_ID, "collect_creator_fee")
            .signer_mut(creator.pubkey())
            .readonly(pool.authority)
            .mutable(pool.state)
            .readonly(self.amm_config)
            .mutable(pool.vault0)
            .mutable(pool.vault1)
            .readonly(pool.m0.mint)
            .readonly(pool.m1.mint)
            .mutable(pool.user_t0[0])
            .mutable(pool.user_t1[0])
            .readonly(pool.m0.token_program)
            .readonly(pool.m1.token_program)
            .readonly(ATA_PROGRAM)
            .readonly(SYSTEM_PROGRAM)
            .readonly(fee_share)
            .build();
        if send(&mut self.ctx, ix, &creator).is_err() {
            return false;
        }
        if std::env::var("FF_DEBUG_LOGS").is_ok() {
            eprintln!("[FF_DEBUG_OK] collect_creator_fee");
        }
        if let Some(after) = self.view(p) {
            let r = |v: &PoolView| (v.vault0 - v.fees0.min(v.vault0), v.vault1 - v.fees1.min(v.vault1));
            if r(&before) != r(&after) {
                let label = self.pools[p].label.clone();
                self.accounting.push(format!(
                    "[fee-accounting] {label}: collect_creator_fee moved LP reserves {:?} -> {:?}",
                    r(&before),
                    r(&after)
                ));
            }
        }
        true
    }

    /// Mint issuer schedules a new transfer fee on one side of a pool. It takes
    /// effect two epochs later (see action_advance_epoch).
    pub fn action_issuer_set_fee(&mut self, #[range(0..9)] p: usize, side_one: bool, #[range(0..10_001)] bps: u64, #[range(0..1_000_000)] max_fee: u64) -> bool {
        let p = p % NP;
        let m = if side_one { self.pools[p].m1.clone() } else { self.pools[p].m0.clone() };
        if m.profile.transfer_fee_params().is_none() {
            return false;
        }
        let env = TokenEnv { payer: &self.issuer, mint_authority: &self.mint_authority, attacker: &self.issuer };
        let ok = env.issuer_set_transfer_fee(&mut self.ctx, &m, bps.min(10_000) as u16, max_fee);
        if ok && std::env::var("FF_DEBUG_LOGS").is_ok() {
            eprintln!("[FF_DEBUG_OK] issuer_set_fee");
        }
        ok
    }

    pub fn action_advance_epoch(&mut self) -> bool {
        advance_epoch(&mut self.ctx);
        true
    }

    /// Harness self-test, off unless FF_CANARY=1: skim one base unit from a
    /// vault outside the program (the smallest possible value leak). With the
    /// canary on, the share-value invariant must fire; if it does not, the
    /// harness is blind and a clean run means nothing.
    pub fn action_canary_skim(&mut self, #[range(0..9)] p: usize) -> bool {
        if std::env::var("FF_CANARY").is_err() || !self.pools[p % NP].live {
            return false;
        }
        let vault = self.pools[p % NP].vault0;
        self.ctx
            .update_account(&vault, |data| {
                // SPL token account layout: amount at bytes 64..72.
                let amt = u64::from_le_bytes(data[64..72].try_into().unwrap());
                data[64..72].copy_from_slice(&amt.saturating_sub(1).to_le_bytes());
            })
            .is_ok()
    }
}

#[invariant_test]
fn amm_invariants(fixture: &mut AmmFixture) {
    for p in 0..NP {
        if !fixture.pools[p].live {
            continue;
        }
        let Some(v) = fixture.view(p) else { continue };
        let label = fixture.pools[p].label.clone();
        fuzz_assert!(
            v.vault0 >= v.fees0 && v.vault1 >= v.fees1,
            "[solvency] {label}: vaults ({}, {}) hold less than booked fees ({}, {})",
            v.vault0, v.vault1, v.fees0, v.fees1
        );
        let (r0, r1) = (v.vault0.saturating_sub(v.fees0), v.vault1.saturating_sub(v.fees1));
        if let Some(msg) = fixture.pools[p].share.observe(&label, r0, r1, v.lp_supply) {
            fuzz_assert!(false, "{}", msg);
        }
    }
    if let Some(msg) = fixture.accounting.first() {
        fuzz_assert!(false, "{}", msg);
    }
}
