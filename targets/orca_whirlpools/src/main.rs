//! Orca Whirlpools × Token-2022 mint matrix, and the Pinocchio port against
//! the Anchor code it replaced.
//!
//! Commit 822f213 moved increase/decrease liquidity (v1 and v2) to
//! hand-written Pinocchio handlers and stubbed out the Anchor ones. Upgrade-diff
//! mode runs every fuzzed step against the port and against the commit just
//! before it, so any difference in outcome or resulting state is a behaviour
//! change in that commit:
//!
//!   FF_PROGRAM_SO=program/reference/whirlpool_822f213.so \
//!   FF_DIFF_SO=program/reference/whirlpool_71569ae.so \
//!     crucible run -C targets/orca_whirlpools orca_whirlpools whirlpool_invariants --release --timeout 900
//!
//! See program/SOURCE.md for how the two reference builds are made.
//!
//! Preflight (setup): each Token-2022 extension is accepted or rejected at
//! pool creation as `is_supported_token_mint` documents, with and without a
//! token badge.
//!
//! Checks after every action, none of which model the concentrated-liquidity
//! maths:
//! * exit solvency: on a scratch copy of the pool last touched, every position
//!   withdraws all liquidity and collects its fees, then the protocol collects
//!   its fees. Every step must succeed, and the pool's active liquidity must
//!   end at zero. A rounding error in any LP's favour makes the last exit fail;
//! * round trip: adding liquidity and removing the same liquidity at once never
//!   returns more of either token than was paid;
//! * slippage on what arrives: measured on the user's token accounts, as on
//!   CP-Swap (exact bound must pass, one unit tighter must fail);
//! * vaults hold at least the protocol fees owed;
//! * compute: no instruction exceeds FF_CU_LIMIT or dies on the meter.

use crucible_fuzzer::anchor_lang::prelude::Clock;
use crucible_fuzzer::*;
use fuzzforge_scenarios::anchor::{account_discriminator, det_keypair, read_i32, read_pubkey, read_u128, read_u64, AnchorIx};
use fuzzforge_scenarios::invariants::summarize_logs;
use fuzzforge_scenarios::token2022::{read_token_account, MintHandle, MintProfile, TokenEnv, SPL_TOKEN_ID};
use fuzzforge_scenarios::{compute, diff};
use solana_account::Account;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use std::rc::Rc;

use crucible_fuzzer::anchor_lang::solana_program::instruction::Instruction;

const PROGRAM_ID: Pubkey = Pubkey::from_str_const("whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc");
const MEMO: Pubkey = Pubkey::from_str_const("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
const ATA_PROGRAM: Pubkey = Pubkey::from_str_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
const SYSVAR_RENT: Pubkey = Pubkey::from_str_const("SysvarRent111111111111111111111111111111111");
const SYSTEM_PROGRAM: Pubkey = Pubkey::from_str_const("11111111111111111111111111111111");

const SOL: u64 = 1_000_000_000;
const USER_TOKENS: u64 = 1_000_000_000_000_000;
const DECIMALS: u8 = 6;
const START_TS: i64 = 1_700_000_000;

const TICK_SPACING: u16 = 64;
const ARRAY_SPAN: i32 = 88 * TICK_SPACING as i32;
/// Tick arrays initialised for every pool; positions and swaps stay inside.
const ARRAY_STARTS: [i32; 5] = [-2 * ARRAY_SPAN, -ARRAY_SPAN, 0, ARRAY_SPAN, 2 * ARRAY_SPAN];
const LOWEST_TICK: i32 = -2 * ARRAY_SPAN;
const HIGHEST_TICK: i32 = 3 * ARRAY_SPAN; // exclusive
// Extreme-price tick arrays, initialised only when FF_EDGE is set. Starts are
// multiples of ARRAY_SPAN (88*64) so they are valid array starts. The low
// start sits below MIN_TICK (-443636); the program allows a left-edge array
// there. Usable ticks stay multiples of 64 inside [MIN_USABLE, MAX_USABLE].
const EDGE_LO_START: i32 = -79 * ARRAY_SPAN; // -444928, covers [-444928, -439296)
const EDGE_HI_START: i32 = 78 * ARRAY_SPAN; //  439296, covers [ 439296,  444928)
const MIN_USABLE_TICK: i32 = -443584; // -6931 * 64, >= MIN_TICK
const MAX_USABLE_TICK: i32 = 443584; //   6931 * 64, <= MAX_TICK
const LO_HI_TICK: i32 = EDGE_LO_START + ARRAY_SPAN - 64; // -439360, top of low array
const HI_LO_TICK: i32 = EDGE_HI_START; // 439296, bottom of high array

fn edge_enabled() -> bool {
    std::env::var("FF_EDGE").is_ok()
}
const FEE_RATE: u16 = 3_000; // 0.3%, hundredths of a basis point
const PROTOCOL_FEE_RATE: u16 = 1_300; // 13% of fees, basis points
const SQRT_PRICE_ONE: u128 = 1 << 64;
const MIN_SQRT_PRICE: u128 = 4_295_048_016;
const MAX_SQRT_PRICE: u128 = 79_226_673_515_401_279_992_447_579_055;
const MAX_POSITIONS: usize = 8;

// Whirlpool (Borsh) field offsets, discriminator included.
const W_LIQUIDITY: usize = 49;
const W_SQRT_PRICE: usize = 65;
const W_TICK: usize = 81;
const W_PROTOCOL_OWED_A: usize = 85;
const W_PROTOCOL_OWED_B: usize = 93;
const W_MINT_A: usize = 101;
// Position (Borsh) field offsets.
const P_LIQUIDITY: usize = 72;

use MintProfile::*;

/// (side A profile, side B profile). Badge-gated profiles get a token badge.
const POOLS: [(MintProfile, MintProfile); 8] = [
    (SplToken, SplToken),
    (SplToken, TransferFee),
    (TransferFee, TransferFeeCapped),
    (TransferFeeMax, SplToken),
    (Plain2022, InterestBearing),
    (FreezeAuthority, SplToken),
    (PermanentDelegate, TransferFee),
    (TransferFeeCapped, SplToken),
];
const NP: usize = POOLS.len();
const NU: usize = 2;

fn needs_badge(p: MintProfile) -> bool {
    matches!(p, FreezeAuthority | PermanentDelegate | TransferHook)
}

#[derive(Clone)]
struct Position {
    owner: usize,
    mint: Rc<Keypair>,
    address: Pubkey,
    token_account: Pubkey,
    lower: i32,
    upper: i32,
}

#[derive(Clone)]
struct Pool {
    label: String,
    ma: MintHandle,
    mb: MintHandle,
    state: Pubkey,
    vault_a: Pubkey,
    vault_b: Pubkey,
    oracle: Pubkey,
    user_a: [Pubkey; NU],
    user_b: [Pubkey; NU],
    fees_to_a: Pubkey,
    fees_to_b: Pubkey,
    positions: Vec<Position>,
    opened: usize,
    live: bool,
}

impl Pool {
    fn both_spl(&self) -> bool {
        self.ma.token_program == SPL_TOKEN_ID && self.mb.token_program == SPL_TOKEN_ID
    }
}

#[derive(Clone)]
struct Fixture {
    ctx: TestContext,
    reference: Option<TestContext>,
    users: [Rc<Keypair>; NU],
    protocol_authority: Rc<Keypair>,
    mint_authority: Rc<Keypair>,
    issuer: Rc<Keypair>,
    config: Pubkey,
    fee_tier: Pubkey,
    pools: Vec<Pool>,
    last_pool: Option<usize>,
    violations: Vec<String>,
}

fn pda(seeds: &[&[u8]]) -> Pubkey {
    Pubkey::find_program_address(seeds, &PROGRAM_ID).0
}

fn tick_array(pool: &Pubkey, start: i32) -> Pubkey {
    pda(&[b"tick_array", pool.as_ref(), start.to_string().as_bytes()])
}

fn array_start(tick: i32) -> i32 {
    tick.div_euclid(ARRAY_SPAN) * ARRAY_SPAN
}

fn debug_ok(what: &str) {
    if std::env::var("FF_DEBUG_LOGS").is_ok() {
        eprintln!("[FF_DEBUG_OK] {what}");
    }
}

struct Failure {
    msg: String,
    out_of_compute: bool,
}

fn send(ctx: &mut TestContext, ix: Instruction, signers: &[&Keypair]) -> Result<u64, Failure> {
    match ctx.raw_call(ix).signers(signers).send() {
        Ok(o) if o.is_success() => Ok(o.compute_units().unwrap_or(0)),
        Ok(o) => {
            if std::env::var("FF_DEBUG_LOGS").is_ok() {
                eprintln!("[FF_DEBUG] {}", o.logs().join("\n[FF_DEBUG] "));
            }
            Err(Failure { msg: summarize_logs(o.logs()), out_of_compute: compute::exhausted(o.logs()) })
        }
        Err(e) => Err(Failure { msg: e.to_string(), out_of_compute: false }),
    }
}

fn write_program_account(ctx: &mut TestContext, address: Pubkey, data: Vec<u8>) {
    ctx.write_account(&address, Account { lamports: 10 * SOL, data, owner: PROGRAM_ID, executable: false, rent_epoch: 0 }).unwrap();
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

#[derive(Clone, Copy, Debug)]
struct WhirlpoolView {
    liquidity: u128,
    sqrt_price: u128,
    tick: i32,
    owed_a: u64,
    owed_b: u64,
}

/// How a liquidity instruction is called.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Method {
    V1,
    V2,
    ByTokenAmounts,
}

impl Fixture {
    fn view_in(ctx: &TestContext, pool: &Pubkey) -> Option<WhirlpoolView> {
        let d = ctx.svm.get_account(pool)?.data;
        (d.len() >= W_MINT_A).then(|| WhirlpoolView {
            liquidity: read_u128(&d, W_LIQUIDITY),
            sqrt_price: read_u128(&d, W_SQRT_PRICE),
            tick: read_i32(&d, W_TICK),
            owed_a: read_u64(&d, W_PROTOCOL_OWED_A),
            owed_b: read_u64(&d, W_PROTOCOL_OWED_B),
        })
    }

    fn view(&self, p: usize) -> Option<WhirlpoolView> {
        Self::view_in(&self.ctx, &self.pools[p].state)
    }

    fn position_liquidity(ctx: &TestContext, position: &Pubkey) -> u128 {
        ctx.svm.get_account(position).map_or(0, |a| if a.data.len() >= P_LIQUIDITY + 16 { read_u128(&a.data, P_LIQUIDITY) } else { 0 })
    }

    fn bal(&self, account: &Pubkey) -> u64 {
        read_token_account(&self.ctx, account).amount
    }

    fn each<R>(&mut self, step: impl Fn(&mut TestContext) -> R) -> R {
        let r = step(&mut self.ctx);
        if let Some(reference) = self.reference.as_mut() {
            step(reference);
        }
        r
    }

    fn exec(&mut self, name: &'static str, p: usize, ix: Instruction, signers: &[&Keypair]) -> Result<(), String> {
        self.last_pool = Some(p);
        let lane = self.pools[p].label.clone();
        let candidate = send(&mut self.ctx, ix.clone(), signers);
        match &candidate {
            Ok(cu) => self.violations.extend(compute::observe("candidate", name, &lane, *cu)),
            Err(f) if f.out_of_compute => self.violations.push(format!("[compute] {lane}: {name} ran out of compute budget: {}", f.msg)),
            Err(_) => {}
        }
        let candidate = candidate.map_err(|f| f.msg);
        if let Some(reference) = self.reference.as_mut() {
            let other = send(reference, ix, signers);
            if let Ok(cu) = &other {
                compute::observe("reference", name, &lane, *cu);
            }
            let other = other.map_err(|f| f.msg);
            if let Some(d) = diff::outcome_difference(name, &candidate, &other) {
                self.violations.push(format!("[upgrade-diff] {lane}: {d}"));
            }
        }
        candidate.map(|_| ())
    }

    fn dry_run<const N: usize>(&self, ixs: &[Instruction], signers: &[&Keypair], watch: [Pubkey; N]) -> Option<[u64; N]> {
        let mut scratch = self.ctx.clone();
        for ix in ixs {
            send(&mut scratch, ix.clone(), signers).ok()?;
        }
        Some(watch.map(|a| read_token_account(&scratch, &a).amount))
    }

    fn pool_difference(&self, p: usize) -> Option<String> {
        let reference = self.reference.as_ref()?;
        let pool = &self.pools[p];
        let mut accounts: Vec<(&str, Pubkey)> = vec![("whirlpool", pool.state), ("vault A", pool.vault_a), ("vault B", pool.vault_b)];
        for start in ARRAY_STARTS {
            accounts.push(("tick array", tick_array(&pool.state, start)));
        }
        for pos in &pool.positions {
            accounts.push(("position", pos.address));
        }
        for u in 0..NU {
            accounts.push(("user token A account", pool.user_a[u]));
            accounts.push(("user token B account", pool.user_b[u]));
        }
        diff::first_difference(&self.ctx, reference, &accounts).map(|d| format!("[upgrade-diff] {}: {d}", pool.label))
    }

    // ---- instruction builders -------------------------------------------

    fn liquidity_ix(&self, p: usize, k: usize, method: Method, increase: bool, liquidity: u128, limit_a: u64, limit_b: u64) -> Instruction {
        let pool = &self.pools[p];
        let pos = &pool.positions[k];
        let user = self.users[pos.owner].pubkey();
        let (lower, upper) = (tick_array(&pool.state, array_start(pos.lower)), tick_array(&pool.state, array_start(pos.upper)));
        let b = match (method, increase) {
            (Method::V1, true) => AnchorIx::new(PROGRAM_ID, "increase_liquidity").u128(liquidity).u64(limit_a).u64(limit_b),
            (Method::V1, false) => AnchorIx::new(PROGRAM_ID, "decrease_liquidity").u128(liquidity).u64(limit_a).u64(limit_b),
            (Method::V2, true) => AnchorIx::new(PROGRAM_ID, "increase_liquidity_v2").u128(liquidity).u64(limit_a).u64(limit_b).option_tag(false),
            (Method::V2, false) | (Method::ByTokenAmounts, false) => {
                AnchorIx::new(PROGRAM_ID, "decrease_liquidity_v2").u128(liquidity).u64(limit_a).u64(limit_b).option_tag(false)
            }
            (Method::ByTokenAmounts, true) => AnchorIx::new(PROGRAM_ID, "increase_liquidity_by_token_amounts_v2")
                .u8(0)
                .u64(limit_a)
                .u64(limit_b)
                .u128(MIN_SQRT_PRICE)
                .u128(MAX_SQRT_PRICE)
                .option_tag(false),
        };
        let b = if method == Method::V1 {
            b.mutable(pool.state)
                .readonly(SPL_TOKEN_ID)
                .signer(user)
                .mutable(pos.address)
                .readonly(pos.token_account)
                .mutable(pool.user_a[pos.owner])
                .mutable(pool.user_b[pos.owner])
                .mutable(pool.vault_a)
                .mutable(pool.vault_b)
                .mutable(lower)
                .mutable(upper)
        } else {
            b.mutable(pool.state)
                .readonly(pool.ma.token_program)
                .readonly(pool.mb.token_program)
                .readonly(MEMO)
                .signer(user)
                .mutable(pos.address)
                .readonly(pos.token_account)
                .readonly(pool.ma.mint)
                .readonly(pool.mb.mint)
                .mutable(pool.user_a[pos.owner])
                .mutable(pool.user_b[pos.owner])
                .mutable(pool.vault_a)
                .mutable(pool.vault_b)
                .mutable(lower)
                .mutable(upper)
        };
        b.build()
    }

    fn update_fees_ix(&self, p: usize, k: usize) -> Instruction {
        let pool = &self.pools[p];
        let pos = &pool.positions[k];
        AnchorIx::new(PROGRAM_ID, "update_fees_and_rewards")
            .mutable(pool.state)
            .mutable(pos.address)
            .readonly(tick_array(&pool.state, array_start(pos.lower)))
            .readonly(tick_array(&pool.state, array_start(pos.upper)))
            .build()
    }

    fn collect_fees_ix(&self, p: usize, k: usize) -> Instruction {
        let pool = &self.pools[p];
        let pos = &pool.positions[k];
        AnchorIx::new(PROGRAM_ID, "collect_fees_v2")
            .option_tag(false)
            .readonly(pool.state)
            .signer(self.users[pos.owner].pubkey())
            .mutable(pos.address)
            .readonly(pos.token_account)
            .readonly(pool.ma.mint)
            .readonly(pool.mb.mint)
            .mutable(pool.user_a[pos.owner])
            .mutable(pool.vault_a)
            .mutable(pool.user_b[pos.owner])
            .mutable(pool.vault_b)
            .readonly(pool.ma.token_program)
            .readonly(pool.mb.token_program)
            .readonly(MEMO)
            .build()
    }

    fn collect_protocol_fees_ix(&self, p: usize) -> Instruction {
        let pool = &self.pools[p];
        AnchorIx::new(PROGRAM_ID, "collect_protocol_fees_v2")
            .option_tag(false)
            .readonly(self.config)
            .mutable(pool.state)
            .signer(self.protocol_authority.pubkey())
            .readonly(pool.ma.mint)
            .readonly(pool.mb.mint)
            .mutable(pool.vault_a)
            .mutable(pool.vault_b)
            .mutable(pool.fees_to_a)
            .mutable(pool.fees_to_b)
            .readonly(pool.ma.token_program)
            .readonly(pool.mb.token_program)
            .readonly(MEMO)
            .build()
    }

    fn swap_ix(&self, p: usize, u: usize, a_to_b: bool, exact_in: bool, amount: u64, threshold: u64) -> Option<Instruction> {
        let pool = &self.pools[p];
        let v = self.view(p)?;
        let s0 = array_start(v.tick);
        let step = if a_to_b { -ARRAY_SPAN } else { ARRAY_SPAN };
        let arrays = [s0, s0 + step, s0 + 2 * step].map(|s| tick_array(&pool.state, s));
        Some(
            AnchorIx::new(PROGRAM_ID, "swap_v2")
                .u64(amount)
                .u64(threshold)
                .u128(if a_to_b { MIN_SQRT_PRICE } else { MAX_SQRT_PRICE })
                .bool(exact_in)
                .bool(a_to_b)
                .option_tag(false)
                .readonly(pool.ma.token_program)
                .readonly(pool.mb.token_program)
                .readonly(MEMO)
                .signer(self.users[u].pubkey())
                .mutable(pool.state)
                .readonly(pool.ma.mint)
                .readonly(pool.mb.mint)
                .mutable(pool.user_a[u])
                .mutable(pool.vault_a)
                .mutable(pool.user_b[u])
                .mutable(pool.vault_b)
                .mutable(arrays[0])
                .mutable(arrays[1])
                .mutable(arrays[2])
                .mutable(pda(&[b"oracle", pool.state.as_ref()]))
                .build(),
        )
    }

    // ---- actions with checks --------------------------------------------

    /// Add or remove `liquidity` on position `k`, with `bound` as on CP-Swap:
    /// 0/1 open, 2 exact (must succeed), 3 one unit too tight (must fail).
    fn change_liquidity(&mut self, p: usize, k: usize, method: Method, increase: bool, liquidity: u128, bound: u64, tight_b: bool, amounts: (u64, u64)) -> bool {
        let pool = self.pools[p].clone();
        let pos = pool.positions[k].clone();
        let user = self.users[pos.owner].clone();
        let name: &'static str = match (method, increase) {
            (Method::V1, true) => "increase_liquidity",
            (Method::V1, false) => "decrease_liquidity",
            (Method::V2, true) => "increase_liquidity_v2",
            (Method::ByTokenAmounts, true) => "increase_liquidity_by_token_amounts_v2",
            (_, false) => "decrease_liquidity_v2",
        };
        let watch = [pool.user_a[pos.owner], pool.user_b[pos.owner]];
        let before = watch.map(|a| self.bal(&a));
        let moved = |after: &[u64; 2]| -> [u64; 2] {
            if increase {
                [before[0].saturating_sub(after[0]), before[1].saturating_sub(after[1])]
            } else {
                [after[0].saturating_sub(before[0]), after[1].saturating_sub(before[1])]
            }
        };
        let by_amounts = method == Method::ByTokenAmounts && increase;
        let open = if increase { u64::MAX } else { 0 };
        let open_ix = self.liquidity_ix(p, k, method, increase, liquidity, open, open);

        // Round trip: add then remove the same liquidity at once; the user
        // must not end up with more of either token.
        if increase && !by_amounts {
            let out = self.liquidity_ix(p, k, if method == Method::V1 { Method::V1 } else { Method::V2 }, false, liquidity, 0, 0);
            if let Some(after) = self.dry_run(&[open_ix.clone(), out], &[&*user], watch) {
                for side in 0..2 {
                    if after[side] > before[side] {
                        self.violations.push(format!(
                            "[round-trip] {}: {name} then decrease of {liquidity} liquidity returned {} more of token {} than was paid",
                            pool.label,
                            after[side] - before[side],
                            ["A", "B"][side]
                        ));
                    }
                }
            }
        }

        let mut limits = if by_amounts { [amounts.0, amounts.1] } else { [open, open] };
        let mut quoted = None;
        if bound >= 2 && !by_amounts {
            let Some(after) = self.dry_run(&[open_ix.clone()], &[&*user], watch) else { return false };
            limits = moved(&after);
            quoted = Some(limits);
            if bound == 3 {
                let side = tight_b as usize;
                limits[side] = if increase {
                    match limits[side].checked_sub(1) {
                        Some(v) => v,
                        None => return false,
                    }
                } else {
                    limits[side] + 1
                };
            }
        }
        let ix = self.liquidity_ix(p, k, method, increase, liquidity, limits[0], limits[1]);
        let result = self.exec(name, p, ix, &[&*user]);
        if let Err(e) = result {
            if let (2, Some(q)) = (bound, quoted) {
                self.violations.push(format!("[slippage] {}: {name} of {liquidity} rejected limits ({}, {}) equal to what it moves: {e}", pool.label, q[0], q[1]));
            }
            if bound == 3 {
                debug_ok(&format!("{name} tight limit rejected"));
            }
            return false;
        }
        debug_ok(name);
        let got = moved(&watch.map(|a| self.bal(&a)));
        for side in 0..2 {
            let broken = if increase { got[side] > limits[side] } else { got[side] < limits[side] };
            if broken {
                let (what, rel) = if increase { ("took", "above the maximum") } else { ("delivered", "below the minimum") };
                self.violations.push(format!(
                    "[slippage] {}: {name} {what} {} of token {} {rel} {} the user signed",
                    pool.label,
                    got[side],
                    ["A", "B"][side],
                    limits[side]
                ));
            }
        }
        true
    }

    /// On a scratch copy: every position exits and collects, then the
    /// protocol collects. All must succeed and active liquidity must reach 0.
    fn exit_check(&self, p: usize) -> Option<String> {
        let pool = &self.pools[p];
        if !pool.live {
            return None;
        }
        let mut scratch = self.ctx.clone();
        let label = &pool.label;
        for (k, pos) in pool.positions.iter().enumerate() {
            let user = self.users[pos.owner].clone();
            let liq = Self::position_liquidity(&scratch, &pos.address);
            if liq > 0 {
                let ix = self.liquidity_ix(p, k, Method::V2, false, liq, 0, 0);
                if let Err(e) = send(&mut scratch, ix, &[&*user]) {
                    return Some(format!("[exit] {label}: position {k} cannot withdraw its {liq} liquidity: {}", e.msg));
                }
            }
            // A position with no liquidity settled its fees when its liquidity
            // last changed; update_fees_and_rewards rejects it (LiquidityZero).
            if let Err(e) = send(&mut scratch, self.collect_fees_ix(p, k), &[&*user]) {
                return Some(format!("[exit] {label}: position {k} cannot collect its fees: {}", e.msg));
            }
        }
        if let Err(e) = send(&mut scratch, self.collect_protocol_fees_ix(p), &[&*self.protocol_authority]) {
            return Some(format!("[exit] {label}: protocol cannot collect its fees after every LP exited: {}", e.msg));
        }
        let v = Self::view_in(&scratch, &pool.state)?;
        (v.liquidity != 0).then(|| format!("[exit] {label}: {} active liquidity left after every position withdrew", v.liquidity))
    }

    fn scaled(reference: u64, ppm: u64, dust: bool) -> u64 {
        if dust {
            ppm % 10_000 + 1
        } else {
            ((reference as u128 * ppm as u128) / 1_000_000).max(1) as u64
        }
    }

    fn ticks(lower_slot: u64, width: u64) -> Option<(i32, i32)> {
        let lower = LOWEST_TICK + (lower_slot as i32) * TICK_SPACING as i32;
        let upper = lower + (width.max(1) as i32) * TICK_SPACING as i32;
        (lower >= LOWEST_TICK && upper < HIGHEST_TICK).then_some((lower, upper))
    }

    /// A position wholly inside one extreme-price tick array (FF_EDGE). Both
    /// ticks are multiples of 64 within one initialised edge array, so the
    /// liquidity maths runs at near-min or near-max sqrt price.
    fn ticks_in_edge(high: bool, offset: u64, width: u64) -> Option<(i32, i32)> {
        let w = (width.max(1) as i32) * TICK_SPACING as i32;
        let off = (offset as i32) * TICK_SPACING as i32;
        let (lower, upper) = if high {
            let lower = (HI_LO_TICK + off).min(MAX_USABLE_TICK - TICK_SPACING as i32);
            (lower, (lower + w).min(MAX_USABLE_TICK))
        } else {
            let upper = (LO_HI_TICK - off).max(MIN_USABLE_TICK + TICK_SPACING as i32);
            ((upper - w).max(MIN_USABLE_TICK), upper)
        };
        (lower < upper).then_some((lower, upper))
    }

    // ---- world -----------------------------------------------------------

    fn build(so: &str, announce: bool) -> Self {
        let mut ctx = TestContext::new();
        ctx.add_program(&PROGRAM_ID, so).unwrap_or_else(|e| panic!("load {so}: {e:?}"));
        set_time(&mut ctx, START_TS);

        let users = [Rc::new(det_keypair("wp-user-0")), Rc::new(det_keypair("wp-user-1"))];
        let protocol_authority = Rc::new(det_keypair("wp-protocol-fees"));
        let mint_authority = Rc::new(det_keypair("wp-mint-authority"));
        let issuer = Rc::new(det_keypair("wp-issuer"));
        for kp in users.iter().chain([&protocol_authority, &mint_authority, &issuer]) {
            ctx.create_account().pubkey(kp.pubkey()).lamports(1_000 * SOL).owner(SYSTEM_PROGRAM).create().unwrap();
        }

        // Config and fee tier are written directly: on the mainnet build their
        // initialisers require Orca's admin key.
        let config = det_keypair("wp-config").pubkey();
        let mut d = account_discriminator("WhirlpoolsConfig").to_vec();
        d.extend_from_slice(protocol_authority.pubkey().as_ref()); // fee_authority
        d.extend_from_slice(protocol_authority.pubkey().as_ref()); // collect_protocol_fees_authority
        d.extend_from_slice(protocol_authority.pubkey().as_ref()); // reward_emissions_super_authority
        d.extend_from_slice(&PROTOCOL_FEE_RATE.to_le_bytes());
        d.extend_from_slice(&0u16.to_le_bytes()); // feature_flags
        assert_eq!(d.len(), 108, "WhirlpoolsConfig::LEN");
        write_program_account(&mut ctx, config, d);

        let fee_tier = pda(&[b"fee_tier", config.as_ref(), &TICK_SPACING.to_le_bytes()]);
        let mut d = account_discriminator("FeeTier").to_vec();
        d.extend_from_slice(config.as_ref());
        d.extend_from_slice(&TICK_SPACING.to_le_bytes());
        d.extend_from_slice(&FEE_RATE.to_le_bytes());
        assert_eq!(d.len(), 44, "FeeTier::LEN");
        write_program_account(&mut ctx, fee_tier, d);

        let mut f = Self {
            ctx,
            reference: None,
            users,
            protocol_authority: protocol_authority.clone(),
            mint_authority: mint_authority.clone(),
            issuer: issuer.clone(),
            config,
            fee_tier,
            pools: Vec::new(),
            last_pool: None,
            violations: Vec::new(),
        };

        // ---- Preflight: mint support policy, with and without a badge --------
        let policy: [(MintProfile, bool, bool); 8] = [
            // (profile, accepted without badge, accepted with badge)
            (TransferFee, true, true),
            (TransferFeeCapped, true, true),
            (TransferFeeMax, true, true),
            (InterestBearing, true, true),
            (PermanentDelegate, false, true),
            (TransferHook, false, true),
            (FreezeAuthority, false, true),
            (NonTransferable, false, false),
        ];
        for (i, (profile, without, with)) in policy.into_iter().enumerate() {
            for badge in [false, true] {
                let mut probe = f.clone();
                let r = probe.create_pool(&format!("pf-{i}-{badge}"), profile, SplToken, badge, false).map(|_| ());
                let expect = if badge { with } else { without };
                let verdict = match (&r, expect) {
                    (Ok(()), true) => "accepted, as documented".to_string(),
                    (Err(_), false) => "rejected, as documented".to_string(),
                    (Ok(()), false) => "ACCEPTED but documented as unsupported".to_string(),
                    (Err(e), true) => format!("REJECTED but documented as supported: {e}"),
                };
                if announce {
                    println!("[FF_PREFLIGHT] [mint-policy] {} {}: {verdict}", profile.name(), if badge { "with badge" } else { "without badge" });
                }
            }
        }

        // ---- Pools under test ------------------------------------------------
        for (p, (pa, pb)) in POOLS.into_iter().enumerate() {
            let badge = needs_badge(pa) || needs_badge(pb);
            match f.create_pool(&format!("pool-{p}"), pa, pb, badge, true) {
                Ok(mut pool) => {
                    pool.label = format!("pool{p}[{} / {}]", pool.ma.profile.name(), pool.mb.profile.name());
                    f.pools.push(pool);
                }
                Err(e) => {
                    println!("[FF_PREFLIGHT] [setup] pool{p} failed: {e}");
                    panic!("pool setup failed");
                }
            }
        }
        // Seed liquidity: user 0 opens a wide position in every pool.
        for p in 0..NP {
            if f.open_position(p, 0, -ARRAY_SPAN, 2 * ARRAY_SPAN) {
                let ok = f.change_liquidity(p, 0, Method::V2, true, 1_000_000_000_000, 0, false, (0, 0));
                if !ok && announce {
                    println!("[FF_PREFLIGHT] [setup] {}: seed liquidity failed", f.pools[p].label);
                }
            } else if announce {
                println!("[FF_PREFLIGHT] [setup] {}: seed position failed", f.pools[p].label);
            }
        }
        f.violations.clear();
        f
    }

    /// Mints, badges, pool, tick arrays and user accounts. `full` funds users
    /// and prepares everything the fuzz actions need.
    fn create_pool(&mut self, tag: &str, pa: MintProfile, pb: MintProfile, badge: bool, full: bool) -> Result<Pool, String> {
        let funder = self.users[0].clone();
        let env = TokenEnv { payer: &funder, mint_authority: &self.mint_authority, attacker: &self.issuer };
        let x = env.create_mint(&mut self.ctx, pa, &det_keypair(&format!("{tag}-a")), DECIMALS).map_err(|e| e.to_string())?;
        let y = env.create_mint(&mut self.ctx, pb, &det_keypair(&format!("{tag}-b")), DECIMALS).map_err(|e| e.to_string())?;
        let (ma, mb) = if x.mint < y.mint { (x, y) } else { (y, x) };
        let badge_of = |m: &Pubkey| pda(&[b"token_badge", self.config.as_ref(), m.as_ref()]);
        if badge {
            for m in [&ma, &mb] {
                if needs_badge(m.profile) {
                    let mut d = account_discriminator("TokenBadge").to_vec();
                    d.extend_from_slice(self.config.as_ref());
                    d.extend_from_slice(m.mint.as_ref());
                    d.push(0);
                    write_program_account(&mut self.ctx, badge_of(&m.mint), d);
                }
            }
        }
        let state = pda(&[b"whirlpool", self.config.as_ref(), ma.mint.as_ref(), mb.mint.as_ref(), &TICK_SPACING.to_le_bytes()]);
        let (va, vb) = (det_keypair(&format!("{tag}-vault-a")), det_keypair(&format!("{tag}-vault-b")));
        let ix = AnchorIx::new(PROGRAM_ID, "initialize_pool_v2")
            .u16(TICK_SPACING)
            .u128(SQRT_PRICE_ONE)
            .readonly(self.config)
            .readonly(ma.mint)
            .readonly(mb.mint)
            .readonly(badge_of(&ma.mint))
            .readonly(badge_of(&mb.mint))
            .signer_mut(funder.pubkey())
            .mutable(state)
            .signer_mut(va.pubkey())
            .signer_mut(vb.pubkey())
            .readonly(self.fee_tier)
            .readonly(ma.token_program)
            .readonly(mb.token_program)
            .readonly(SYSTEM_PROGRAM)
            .readonly(SYSVAR_RENT)
            .build();
        send(&mut self.ctx, ix, &[&*funder, &va, &vb]).map_err(|e| e.msg)?;
        let d = self.ctx.svm.get_account(&state).unwrap().data;
        assert_eq!(read_pubkey(&d, W_MINT_A), ma.mint, "Whirlpool layout drifted");
        let mut pool = Pool {
            label: tag.to_string(),
            ma: ma.clone(),
            mb: mb.clone(),
            state,
            vault_a: va.pubkey(),
            vault_b: vb.pubkey(),
            oracle: pda(&[b"oracle", state.as_ref()]),
            user_a: Default::default(),
            user_b: Default::default(),
            fees_to_a: Pubkey::default(),
            fees_to_b: Pubkey::default(),
            positions: Vec::new(),
            opened: 0,
            live: true,
        };
        if !full {
            return Ok(pool);
        }
        let mut starts = ARRAY_STARTS.to_vec();
        if edge_enabled() {
            starts.push(EDGE_LO_START);
            starts.push(EDGE_HI_START);
        }
        for start in starts {
            let ix = AnchorIx::new(PROGRAM_ID, "initialize_tick_array")
                .i32(start)
                .readonly(state)
                .signer_mut(funder.pubkey())
                .mutable(tick_array(&state, start))
                .readonly(SYSTEM_PROGRAM)
                .build();
            send(&mut self.ctx, ix, &[&*funder]).map_err(|e| format!("tick array {start}: {}", e.msg))?;
        }
        for u in 0..NU {
            let owner = self.users[u].pubkey();
            pool.user_a[u] = env.fund(&mut self.ctx, &ma, &owner, USER_TOKENS).map_err(|e| e.to_string())?;
            pool.user_b[u] = env.fund(&mut self.ctx, &mb, &owner, USER_TOKENS).map_err(|e| e.to_string())?;
        }
        let authority = self.protocol_authority.pubkey();
        pool.fees_to_a = env.fund(&mut self.ctx, &ma, &authority, 0).map_err(|e| e.to_string())?;
        pool.fees_to_b = env.fund(&mut self.ctx, &mb, &authority, 0).map_err(|e| e.to_string())?;
        Ok(pool)
    }

    fn open_position(&mut self, p: usize, u: usize, lower: i32, upper: i32) -> bool {
        if self.pools[p].positions.len() >= MAX_POSITIONS {
            return false;
        }
        let n = self.pools[p].opened;
        let pool = self.pools[p].clone();
        let mint = Rc::new(det_keypair(&format!("{}-pos-{n}", pool.state)));
        let (address, bump) = Pubkey::find_program_address(&[b"position", mint.pubkey().as_ref()], &PROGRAM_ID);
        let handle = MintHandle { profile: SplToken, mint: mint.pubkey(), token_program: SPL_TOKEN_ID, decimals: 0 };
        let user = self.users[u].clone();
        let token_account = handle.ata(&user.pubkey());
        let ix = AnchorIx::new(PROGRAM_ID, "open_position")
            .u8(bump)
            .i32(lower)
            .i32(upper)
            .signer_mut(user.pubkey())
            .readonly(user.pubkey())
            .mutable(address)
            .signer_mut(mint.pubkey())
            .mutable(token_account)
            .readonly(pool.state)
            .readonly(SPL_TOKEN_ID)
            .readonly(SYSTEM_PROGRAM)
            .readonly(SYSVAR_RENT)
            .readonly(ATA_PROGRAM)
            .build();
        if self.exec("open_position", p, ix, &[&*user, &*mint]).is_err() {
            return false;
        }
        let pool = &mut self.pools[p];
        pool.opened += 1;
        pool.positions.push(Position { owner: u, mint, address, token_account, lower, upper });
        debug_ok("open_position");
        true
    }

    fn swap(&mut self, p: usize, u: usize, a_to_b: bool, exact_in: bool, amount: u64, bound: u64) -> bool {
        let pool = self.pools[p].clone();
        let user = self.users[u].clone();
        let (in_acct, out_acct) = if a_to_b { (pool.user_a[u], pool.user_b[u]) } else { (pool.user_b[u], pool.user_a[u]) };
        let watch = [in_acct, out_acct];
        let before = watch.map(|a| self.bal(&a));
        let moved = |after: &[u64; 2]| (before[0].saturating_sub(after[0]), after[1].saturating_sub(before[1]));
        let open = if exact_in { 0 } else { u64::MAX };
        let Some(probe) = self.swap_ix(p, u, a_to_b, exact_in, amount, open) else { return false };
        let mut threshold = open;
        let mut quoted = None;
        if bound >= 2 {
            let Some(after) = self.dry_run(&[probe], &[&*user], watch) else { return false };
            let (paid, got) = moved(&after);
            let q = if exact_in { got } else { paid };
            quoted = Some(q);
            threshold = match (bound, exact_in) {
                (2, _) => q,
                (_, true) => q + 1,
                (_, false) => match q.checked_sub(1) {
                    Some(v) => v,
                    None => return false,
                },
            };
        }
        let Some(ix) = self.swap_ix(p, u, a_to_b, exact_in, amount, threshold) else { return false };
        if let Err(e) = self.exec("swap_v2", p, ix, &[&*user]) {
            if let (2, Some(q)) = (bound, quoted) {
                self.violations.push(format!("[slippage] {}: swap_v2 of {amount} rejected a threshold of {q}, exactly what the same swap moves: {e}", pool.label));
            }
            if bound == 3 {
                debug_ok("swap tight threshold rejected");
            }
            return false;
        }
        debug_ok("swap_v2");
        let (paid, got) = moved(&watch.map(|a| self.bal(&a)));
        if exact_in && got < threshold {
            self.violations.push(format!("[slippage] {}: swap_v2 delivered {got}, below the minimum {threshold} the user signed", pool.label));
        }
        if !exact_in && paid > threshold {
            self.violations.push(format!("[slippage] {}: swap_v2 took {paid}, above the maximum {threshold} the user signed", pool.label));
        }
        true
    }
}

#[fuzz_fixture]
impl Fixture {
    pub fn setup() -> Self {
        let so = std::env::var("FF_PROGRAM_SO").unwrap_or_else(|_| "program/whirlpool_mainnet_2026-11-11.so".into());
        let mut f = Self::build(&so, true);
        if let Ok(reference_so) = std::env::var("FF_DIFF_SO") {
            println!("[FF_PREFLIGHT] [upgrade-diff] candidate {so}, reference {reference_so}");
            let g = Self::build(&reference_so, false);
            f.reference = Some(g.ctx);
            for p in 0..NP {
                if let Some(reason) = f.pool_difference(p) {
                    println!("[FF_PREFLIGHT] [upgrade-diff] {} excluded: differs straight after setup: {reason}", f.pools[p].label);
                    f.pools[p].live = false;
                }
            }
        }
        f
    }

    pub fn action_open_position(&mut self, #[range(0..8)] p: usize, #[range(0..2)] u: usize, #[range(0..264)] lower_slot: u64, #[range(1..200)] width: u64) -> bool {
        let p = p % NP;
        let Some((lower, upper)) = Self::ticks(lower_slot, width) else { return false };
        self.pools[p].live && self.open_position(p, u % NU, lower, upper)
    }

    /// Open a position pinned to a near-min or near-max price (FF_EDGE only).
    pub fn action_open_edge_position(&mut self, #[range(0..8)] p: usize, #[range(0..2)] u: usize, high: bool, #[range(0..67)] offset: u64, #[range(1..66)] width: u64) -> bool {
        if !edge_enabled() {
            return false;
        }
        let p = p % NP;
        let Some((lower, upper)) = Self::ticks_in_edge(high, offset, width) else { return false };
        self.pools[p].live && self.open_position(p, u % NU, lower, upper)
    }

    pub fn action_increase(&mut self, #[range(0..8)] p: usize, #[range(0..8)] k: usize, #[range(1..1_000_000)] ppm: u64, #[range(0..28)] shift: u32, #[range(0..4)] bound: u64, tight_b: bool, #[range(0..3)] method: u64) -> bool {
        let p = p % NP;
        if !self.pools[p].live || self.pools[p].positions.is_empty() {
            return false;
        }
        let k = k % self.pools[p].positions.len();
        let method = match method {
            0 if self.pools[p].both_spl() => Method::V1,
            2 => Method::ByTokenAmounts,
            _ => Method::V2,
        };
        let liquidity = (ppm as u128) << shift;
        let amounts = (Self::scaled(1_000_000_000_000, ppm, false), Self::scaled(1_000_000_000_000, ppm.rotate_left(7) % 1_000_000 + 1, false));
        self.change_liquidity(p, k, method, true, liquidity, bound, tight_b, amounts)
    }

    pub fn action_decrease(&mut self, #[range(0..8)] p: usize, #[range(0..8)] k: usize, #[range(1..1_000_001)] ppm: u64, dust: bool, #[range(0..4)] bound: u64, tight_b: bool, v1: bool) -> bool {
        let p = p % NP;
        if !self.pools[p].live || self.pools[p].positions.is_empty() {
            return false;
        }
        let k = k % self.pools[p].positions.len();
        let have = Self::position_liquidity(&self.ctx, &self.pools[p].positions[k].address);
        if have == 0 {
            return false;
        }
        let liquidity = if dust { (ppm as u128 % 1_000).min(have).max(1) } else { (have * ppm as u128 / 1_000_000).max(1) };
        let method = if v1 && self.pools[p].both_spl() { Method::V1 } else { Method::V2 };
        self.change_liquidity(p, k, method, false, liquidity, bound, tight_b, (0, 0))
    }

    pub fn action_reposition(&mut self, #[range(0..8)] p: usize, #[range(0..8)] k: usize, #[range(0..264)] lower_slot: u64, #[range(1..200)] width: u64, #[range(1..1_000_000)] ppm: u64) -> bool {
        let p = p % NP;
        if !self.pools[p].live || self.pools[p].positions.is_empty() {
            return false;
        }
        let k = k % self.pools[p].positions.len();
        let Some((lower, upper)) = Self::ticks(lower_slot, width) else { return false };
        let pool = self.pools[p].clone();
        let pos = pool.positions[k].clone();
        let have = Self::position_liquidity(&self.ctx, &pos.address);
        let new_liquidity = (have.max(1) * ppm as u128 / 500_000).max(1);
        let user = self.users[pos.owner].clone();
        let ta = |t: i32| tick_array(&pool.state, array_start(t));
        let ix = AnchorIx::new(PROGRAM_ID, "reposition_liquidity_v2")
            .i32(lower)
            .i32(upper)
            .u8(0)
            .u128(new_liquidity)
            .u64(0)
            .u64(0)
            .u64(u64::MAX)
            .u64(u64::MAX)
            .option_tag(false)
            .mutable(pool.state)
            .readonly(pool.ma.token_program)
            .readonly(pool.mb.token_program)
            .readonly(MEMO)
            .signer(user.pubkey())
            .signer_mut(user.pubkey())
            .mutable(pos.address)
            .readonly(pos.token_account)
            .readonly(pool.ma.mint)
            .readonly(pool.mb.mint)
            .mutable(pool.user_a[pos.owner])
            .mutable(pool.user_b[pos.owner])
            .mutable(pool.vault_a)
            .mutable(pool.vault_b)
            .mutable(ta(pos.lower))
            .mutable(ta(pos.upper))
            .mutable(ta(lower))
            .mutable(ta(upper))
            .readonly(SYSTEM_PROGRAM)
            .build();
        if self.exec("reposition_liquidity_v2", p, ix, &[&*user]).is_err() {
            return false;
        }
        let pos = &mut self.pools[p].positions[k];
        pos.lower = lower;
        pos.upper = upper;
        debug_ok("reposition_liquidity_v2");
        true
    }

    pub fn action_swap(&mut self, #[range(0..8)] p: usize, #[range(0..2)] u: usize, a_to_b: bool, exact_in: bool, #[range(1..1_000_000)] ppm: u64, dust: bool, #[range(0..4)] bound: u64) -> bool {
        let p = p % NP;
        if !self.pools[p].live {
            return false;
        }
        let pool = &self.pools[p];
        let reference = if a_to_b == exact_in { self.bal(&pool.vault_a) } else { self.bal(&pool.vault_b) };
        let amount = Self::scaled(reference / 4, ppm, dust);
        self.swap(p, u % NU, a_to_b, exact_in, amount, bound)
    }

    pub fn action_collect_fees(&mut self, #[range(0..8)] p: usize, #[range(0..8)] k: usize) -> bool {
        let p = p % NP;
        if !self.pools[p].live || self.pools[p].positions.is_empty() {
            return false;
        }
        let k = k % self.pools[p].positions.len();
        let user = self.users[self.pools[p].positions[k].owner].clone();
        if Self::position_liquidity(&self.ctx, &self.pools[p].positions[k].address) > 0 {
            let ix = self.update_fees_ix(p, k);
            if self.exec("update_fees_and_rewards", p, ix, &[&*user]).is_err() {
                return false;
            }
        }
        let ix = self.collect_fees_ix(p, k);
        let ok = self.exec("collect_fees_v2", p, ix, &[&*user]).is_ok();
        if ok {
            debug_ok("collect_fees_v2");
        }
        ok
    }

    pub fn action_collect_protocol_fees(&mut self, #[range(0..8)] p: usize) -> bool {
        let p = p % NP;
        if !self.pools[p].live {
            return false;
        }
        let ix = self.collect_protocol_fees_ix(p);
        let authority = self.protocol_authority.clone();
        let ok = self.exec("collect_protocol_fees_v2", p, ix, &[&*authority]).is_ok();
        if ok {
            debug_ok("collect_protocol_fees_v2");
        }
        ok
    }

    /// Tokens sent straight into a vault. A CLMM does not read reserves from
    /// vault balances, so this must not change any accounting; it only leaves
    /// dust the exit check has to tolerate.
    pub fn action_donate(&mut self, #[range(0..8)] p: usize, #[range(0..2)] u: usize, side_b: bool, #[range(1..1_000_000)] ppm: u64, dust: bool) -> bool {
        let p = p % NP;
        if !self.pools[p].live {
            return false;
        }
        let pool = &self.pools[p];
        let (mint, vault) = if side_b { (pool.mb.clone(), pool.vault_b) } else { (pool.ma.clone(), pool.vault_a) };
        let amount = Self::scaled(self.bal(&vault), ppm, dust);
        let donor = self.users[u % NU].clone();
        let (authority, issuer) = (self.mint_authority.clone(), self.issuer.clone());
        self.last_pool = Some(p);
        self.each(|ctx| {
            let env = TokenEnv { payer: &donor, mint_authority: &authority, attacker: &issuer };
            env.donate(ctx, &mint, &donor, &vault, amount)
        })
    }

    pub fn action_advance_time(&mut self, #[range(1..86_400)] secs: u64) -> bool {
        let now = self.ctx.svm.get_sysvar::<Clock>().unix_timestamp;
        self.each(|ctx| set_time(ctx, now + secs as i64));
        true
    }

    pub fn action_issuer_set_fee(&mut self, #[range(0..8)] p: usize, side_b: bool, #[range(0..10_001)] bps: u64, #[range(0..1_000_000)] max_fee: u64) -> bool {
        let p = p % NP;
        let m = if side_b { self.pools[p].mb.clone() } else { self.pools[p].ma.clone() };
        if m.profile.transfer_fee_params().is_none() {
            return false;
        }
        let (authority, issuer) = (self.mint_authority.clone(), self.issuer.clone());
        self.each(|ctx| {
            let env = TokenEnv { payer: &issuer, mint_authority: &authority, attacker: &issuer };
            env.issuer_set_transfer_fee(ctx, &m, bps.min(10_000) as u16, max_fee)
        })
    }

    pub fn action_advance_epoch(&mut self) -> bool {
        self.each(advance_epoch);
        true
    }

    /// Harness self-test (FF_CANARY): `1` skims one unit from a vault, which
    /// the exit check must catch once that pool's LPs try to leave; `diff`
    /// skims on the reference build only, which the state comparison must catch.
    pub fn action_canary_skim(&mut self, #[range(0..8)] p: usize, side_b: bool) -> bool {
        let Ok(mode) = std::env::var("FF_CANARY") else { return false };
        let p = p % NP;
        if !self.pools[p].live {
            return false;
        }
        let vault = if side_b { self.pools[p].vault_b } else { self.pools[p].vault_a };
        let skim = |ctx: &mut TestContext| {
            ctx.update_account(&vault, |data| {
                let amt = u64::from_le_bytes(data[64..72].try_into().unwrap());
                data[64..72].copy_from_slice(&amt.saturating_sub(amt / 2 + 1).to_le_bytes());
            })
            .is_ok()
        };
        self.last_pool = Some(p);
        if mode == "diff" {
            self.reference.as_mut().is_some_and(skim)
        } else {
            self.each(skim)
        }
    }
}

#[invariant_test]
fn whirlpool_invariants(fixture: &mut Fixture) {
    for p in 0..NP {
        if !fixture.pools[p].live {
            continue;
        }
        let Some(v) = fixture.view(p) else { continue };
        let pool = &fixture.pools[p];
        let (va, vb) = (fixture.bal(&pool.vault_a), fixture.bal(&pool.vault_b));
        fuzz_assert!(
            va >= v.owed_a && vb >= v.owed_b,
            "[solvency] {}: vaults ({va}, {vb}) hold less than protocol fees owed ({}, {}); sqrt price {}",
            pool.label,
            v.owed_a,
            v.owed_b,
            v.sqrt_price
        );
        if let Some(msg) = fixture.pool_difference(p) {
            fuzz_assert!(false, "{}", msg);
        }
    }
    if let Some(p) = fixture.last_pool {
        if let Some(msg) = fixture.exit_check(p) {
            fuzz_assert!(false, "{}", msg);
        }
    }
    if let Some(msg) = fixture.violations.first() {
        fuzz_assert!(false, "{}", msg);
    }
}
