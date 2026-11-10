//! token_vault × Token-2022 hostile mint matrix.
//!
//! One vault per mint profile, all owned by the same user. The fuzzer drives
//! owner flows (deposit, withdraw, exit, close, re-initialize) and attacker
//! flows (delegate pull, freeze) in random order across profiles, and checks:
//!
//! * custody: a vault balance moves only through the owner's deposit/withdraw;
//! * exit liveness: the owner can always withdraw everything and close;
//! * lifecycle: a live vault cannot be re-initialized.
//!
//!   crucible run -C targets/token_vault token_vault token2022_matrix --release --timeout 60
//!   ... --mutate-accounts   (adds Crucible's account-constraint probes)

use crucible_fuzzer::anchor_lang::solana_program::system_program;
use crucible_fuzzer::*;
use crucible_test_context::TxOutcome;
use fuzzforge_scenarios::invariants::summarize_logs;
use fuzzforge_scenarios::token2022::{read_token_account, MintHandle, MintProfile, TokenEnv};
use fuzzforge_scenarios::{CustodyLedger, LivenessLog};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use std::rc::Rc;

crucible_idl_gen::declare_fuzz_program!("idls/token_vault.json");
use token_vault::{accounts, instruction};

const N: usize = MintProfile::ALL.len();
const SOL: u64 = 1_000_000_000;
const OWNER_TOKENS: u64 = 1_000_000_000_000;
const DECIMALS: u8 = 6;

#[derive(Clone)]
struct Lane {
    mint: MintHandle,
    owner_ata: Pubkey,
    vault_state: Pubkey,
    vault: Pubkey,
    live: bool,
    /// Preflight showed deposits can never succeed for this mint. Reported once
    /// at setup; excluded from per-iteration deposit liveness so it does not
    /// drown out sequence-dependent findings.
    deposit_blocked: bool,
    custody: CustodyLedger,
}

#[derive(Clone)]
struct VaultFixture {
    ctx: TestContext,
    program_id: Pubkey,
    owner: Rc<Keypair>,
    mint_authority: Rc<Keypair>,
    attacker: Rc<Keypair>,
    lanes: Vec<Lane>,
    liveness: LivenessLog,
    lifecycle: Vec<String>,
}

impl VaultFixture {
    fn send_initialize(&mut self, i: usize) -> Result<TxOutcome, String> {
        let l = &self.lanes[i];
        self.ctx
            .program(self.program_id)
            .call(instruction::Initialize {})
            .accounts(accounts::Initialize {
                owner: self.owner.pubkey(),
                mint: l.mint.mint,
                vault_state: l.vault_state,
                vault: l.vault,
                token_program: l.mint.token_program,
            })
            .signers(&[&*self.owner])
            .send()
            .map_err(|e| e.to_string())
    }

    fn send_deposit(&mut self, i: usize, amount: u64) -> Result<TxOutcome, String> {
        let l = &self.lanes[i];
        self.ctx
            .program(self.program_id)
            .call(instruction::Deposit { amount })
            .accounts(accounts::Deposit {
                owner: self.owner.pubkey(),
                mint: l.mint.mint,
                owner_ata: l.owner_ata,
                vault: l.vault,
                vault_state: l.vault_state,
                token_program: l.mint.token_program,
            })
            .signers(&[&*self.owner])
            .send()
            .map_err(|e| e.to_string())
    }

    fn send_withdraw(&mut self, i: usize, amount: u64) -> Result<TxOutcome, String> {
        let l = &self.lanes[i];
        self.ctx
            .program(self.program_id)
            .call(instruction::Withdraw { amount })
            .accounts(accounts::Withdraw {
                owner: self.owner.pubkey(),
                mint: l.mint.mint,
                owner_ata: l.owner_ata,
                vault: l.vault,
                vault_state: l.vault_state,
                token_program: l.mint.token_program,
            })
            .signers(&[&*self.owner])
            .send()
            .map_err(|e| e.to_string())
    }

    fn send_close(&mut self, i: usize) -> Result<TxOutcome, String> {
        let l = &self.lanes[i];
        self.ctx
            .program(self.program_id)
            .call(instruction::Close {})
            .accounts(accounts::Close {
                owner: self.owner.pubkey(),
                mint: l.mint.mint,
                vault: l.vault,
                vault_state: l.vault_state,
                token_program: l.mint.token_program,
            })
            .signers(&[&*self.owner])
            .send()
            .map_err(|e| e.to_string())
    }

    fn vault_amount(&self, i: usize) -> u64 {
        read_token_account(&self.ctx, &self.lanes[i].vault).amount
    }

    fn outcome_detail(r: &Result<TxOutcome, String>) -> String {
        match r {
            Ok(o) => summarize_logs(o.logs()),
            Err(e) => e.clone(),
        }
    }
}

#[fuzz_fixture]
impl VaultFixture {
    pub fn setup() -> Self {
        token_vault::register_schemas();
        let mut ctx = TestContext::new();
        let program_id = Pubkey::new_from_array(token_vault::ID.to_bytes());
        let so = std::env::var("FF_PROGRAM_SO").unwrap_or_else(|_| "program/token_vault.so".into());
        ctx.add_program(&program_id, &so).expect("load token_vault.so");

        let owner = Rc::new(Keypair::new());
        let mint_authority = Rc::new(Keypair::new());
        let attacker = Rc::new(Keypair::new());
        for kp in [&owner, &mint_authority, &attacker] {
            ctx.create_account()
                .pubkey(kp.pubkey())
                .lamports(100 * SOL)
                .owner(system_program::ID)
                .create()
                .unwrap();
        }

        let mut lanes = Vec::with_capacity(N);
        {
            let env = TokenEnv { payer: &owner, mint_authority: &mint_authority, attacker: &attacker };
            for profile in MintProfile::ALL {
                let mint_kp = Keypair::new();
                let mint = env
                    .create_mint(&mut ctx, profile, &mint_kp, DECIMALS)
                    .unwrap_or_else(|e| panic!("create {} mint: {e:#}", profile.name()));
                let owner_ata = env.fund(&mut ctx, &mint, &owner.pubkey(), OWNER_TOKENS).unwrap();
                let (vault_state, _) = Pubkey::find_program_address(
                    &[b"state", owner.pubkey().as_ref(), mint.mint.as_ref()],
                    &program_id,
                );
                let vault = mint.ata(&vault_state);
                lanes.push(Lane {
                    mint,
                    owner_ata,
                    vault_state,
                    vault,
                    live: false,
                    deposit_blocked: false,
                    custody: Default::default(),
                });
            }
        }

        let mut f = Self {
            ctx,
            program_id,
            owner,
            mint_authority,
            attacker,
            lanes,
            liveness: LivenessLog::default(),
            lifecycle: Vec::new(),
        };
        for i in 0..N {
            let r = f.send_initialize(i);
            let ok = matches!(&r, Ok(o) if o.is_success());
            if !ok {
                eprintln!("[setup] initialize failed for {}: {}", f.lanes[i].mint.profile.name(), Self::outcome_detail(&r));
            }
            f.lanes[i].live = ok;
        }

        // Preflight: a deposit of one base unit on a throwaway copy of the
        // state. Mints the program accepts at initialize but can never take
        // deposits for are a design finding, reported once.
        for i in 0..N {
            if !f.lanes[i].live {
                continue;
            }
            let mut probe = f.clone();
            let r = probe.send_deposit(i, 1);
            if !matches!(&r, Ok(o) if o.is_success()) {
                f.lanes[i].deposit_blocked = true;
                println!(
                    "[FF_PREFLIGHT] [liveness:deposit] {}: initialize accepts this mint but every deposit fails: {}",
                    f.lanes[i].mint.profile.name(),
                    Self::outcome_detail(&r)
                );
            }
        }
        f
    }

    pub fn action_deposit(&mut self, #[range(0..7)] m: usize, #[range(1..10_000_000)] amount: u64) -> bool {
        let i = m % N;
        if !self.lanes[i].live || self.lanes[i].deposit_blocked {
            return false;
        }
        let owner_has = read_token_account(&self.ctx, &self.lanes[i].owner_ata);
        let before = self.vault_amount(i);
        let r = self.send_deposit(i, amount);
        let ok = matches!(&r, Ok(o) if o.is_success());
        if ok {
            let received = self.vault_amount(i).saturating_sub(before);
            self.lanes[i].custody.credit(amount, received);
        } else {
            let vault = read_token_account(&self.ctx, &self.lanes[i].vault);
            if owner_has.amount >= amount && !owner_has.frozen && !vault.frozen {
                let name = self.lanes[i].mint.profile.name();
                self.liveness.fail("deposit", name, format!(
                    "deposit of {amount} rejected with sufficient unfrozen balance: {}",
                    Self::outcome_detail(&r)
                ));
            }
        }
        ok
    }

    pub fn action_withdraw(&mut self, #[range(0..7)] m: usize, #[range(1..10_000_000)] amount: u64) -> bool {
        let i = m % N;
        if !self.lanes[i].live {
            return false;
        }
        let before = self.vault_amount(i);
        let r = self.send_withdraw(i, amount);
        let ok = matches!(&r, Ok(o) if o.is_success());
        if ok {
            let removed = before.saturating_sub(self.vault_amount(i));
            self.lanes[i].custody.debit(removed);
        }
        ok
    }

    /// The exit path every vault must support: withdraw the full balance, then
    /// close. A failure here is a funds-stuck finding.
    pub fn action_owner_exit(&mut self, #[range(0..7)] m: usize) -> bool {
        let i = m % N;
        if !self.lanes[i].live {
            return false;
        }
        let name = self.lanes[i].mint.profile.name();
        let bal = self.vault_amount(i);
        if bal > 0 {
            let r = self.send_withdraw(i, bal);
            if !matches!(&r, Ok(o) if o.is_success()) {
                self.liveness.fail("exit", name, format!(
                    "owner cannot withdraw full balance {bal}: {}",
                    Self::outcome_detail(&r)
                ));
                return false;
            }
            let removed = bal - self.vault_amount(i);
            self.lanes[i].custody.debit(removed);
        }
        let view = read_token_account(&self.ctx, &self.lanes[i].vault);
        let r = self.send_close(i);
        if !matches!(&r, Ok(o) if o.is_success()) {
            self.liveness.fail("exit", name, format!(
                "owner cannot close after withdrawing everything (vault amount {}, withheld fees {}, frozen {}): {}",
                view.amount, view.withheld, view.frozen,
                Self::outcome_detail(&r)
            ));
            return false;
        }
        self.lanes[i].live = false;
        self.lanes[i].custody.reset();
        true
    }

    pub fn action_close(&mut self, #[range(0..7)] m: usize) -> bool {
        let i = m % N;
        if !self.lanes[i].live {
            return false;
        }
        let ok = matches!(self.send_close(i), Ok(o) if o.is_success());
        if ok {
            self.lanes[i].live = false;
            self.lanes[i].custody.reset();
        }
        ok
    }

    /// Lifecycle: initialize on a live vault must fail; after close it may
    /// legitimately succeed (close-then-revive starts from an empty vault).
    pub fn action_initialize(&mut self, #[range(0..7)] m: usize) -> bool {
        let i = m % N;
        let was_live = self.lanes[i].live;
        let ok = matches!(self.send_initialize(i), Ok(o) if o.is_success());
        if ok && was_live {
            self.lifecycle.push(format!("[lifecycle] {}: initialize succeeded on a live vault", self.lanes[i].mint.profile.name()));
        }
        if ok {
            self.lanes[i].live = true;
        }
        ok
    }

    /// Attacker tries to move `pct`% of the vault's current balance out using
    /// only their own signature.
    pub fn action_attacker_pull(&mut self, #[range(0..7)] m: usize, #[range(1..101)] pct: u64) -> bool {
        let i = m % N;
        let bal = self.vault_amount(i);
        let amount = (bal as u128 * pct as u128 / 100).max(1) as u64;
        let mint = self.lanes[i].mint.clone();
        let vault = self.lanes[i].vault;
        let env = TokenEnv { payer: &self.attacker, mint_authority: &self.mint_authority, attacker: &self.attacker };
        env.attacker_pull(&mut self.ctx, &mint, &vault, amount)
    }

    pub fn action_attacker_freeze(&mut self, #[range(0..7)] m: usize) -> bool {
        let i = m % N;
        let mint = self.lanes[i].mint.clone();
        let vault = self.lanes[i].vault;
        let env = TokenEnv { payer: &self.attacker, mint_authority: &self.mint_authority, attacker: &self.attacker };
        env.attacker_freeze(&mut self.ctx, &mint, &vault)
    }
}

#[invariant_test]
fn token2022_matrix(fixture: &mut VaultFixture) {
    for i in 0..N {
        let l = &fixture.lanes[i];
        if !l.live {
            continue;
        }
        let actual = read_token_account(&fixture.ctx, &l.vault).amount;
        if let Some(v) = l.custody.check(l.mint.profile.name(), actual) {
            fuzz_assert!(false, "{}", v);
        }
    }
    if let Some(v) = fixture.liveness.first() {
        fuzz_assert!(false, "{}", v);
    }
    if let Some(v) = fixture.lifecycle.first() {
        fuzz_assert!(false, "{}", v);
    }
}
