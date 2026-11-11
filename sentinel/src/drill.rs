//! Drills: fresh transactions against a live pool's current state, from a
//! synthetic user that exists only in the local fork. Each case states the
//! verdict the policy should reach, so a drill run is a pass/fail check that
//! the firewall's rules fire on live state, and stay quiet, as designed.
//!
//! Replaying past mainnet transactions cannot do this: almost all CP-Swap
//! traffic is bots with tight bounds whose transactions fail moments later.

use crate::check::{check_with, Decision};
use crate::cpswap::{token_amount, PoolKeys};
use crate::fork::{Fork, Overlay};
use crate::monitor::load_pools;
use crate::policy::Policy;
use crate::rpc::Rpc;
use anyhow::{bail, Result};
use fuzzforge_scenarios::anchor::{det_keypair, AnchorIx};
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::{Message, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;

const NATIVE_MINT: Pubkey = Pubkey::from_str_const("So11111111111111111111111111111111111111112");
const TOKEN_2022: Pubkey = Pubkey::from_str_const("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
const MEMO_V1: Pubkey = Pubkey::from_str_const("Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo");
const TOKEN_ACCOUNT_RENT: u64 = 2_039_280;

pub struct Case {
    pub name: &'static str,
    pub expect: &'static str,
    pub decision: Decision,
}

fn token_account(mint: &Pubkey, owner: &Pubkey, program: &Pubkey, amount: u64) -> Account {
    let mut d = vec![0u8; 165];
    d[..32].copy_from_slice(mint.as_ref());
    d[32..64].copy_from_slice(owner.as_ref());
    d[64..72].copy_from_slice(&amount.to_le_bytes());
    d[108] = 1; // initialized
    let mut lamports = TOKEN_ACCOUNT_RENT;
    if *mint == NATIVE_MINT {
        d[109..113].copy_from_slice(&1u32.to_le_bytes());
        d[113..121].copy_from_slice(&TOKEN_ACCOUNT_RENT.to_le_bytes());
        lamports += amount;
    }
    Account { lamports, data: d, owner: *program, executable: false, rent_epoch: 0 }
}

fn tx(ixs: &[Instruction], payer: &Pubkey) -> VersionedTransaction {
    let msg = Message::new(ixs, Some(payer));
    let n = msg.header.num_required_signatures as usize;
    VersionedTransaction { signatures: vec![Default::default(); n], message: VersionedMessage::Legacy(msg) }
}

pub fn drill(rpc: &Rpc, policy: &Policy, pool: &Pubkey, candidate_so: Option<&str>) -> Result<Vec<Case>> {
    let program = policy.program_id();
    let keys: PoolKeys = load_pools(rpc, &program, &[*pool])?.remove(0);
    let (_, mints) = rpc.accounts(&[keys.mint0, keys.mint1, keys.vault0])?;
    for (m, acc) in [keys.mint0, keys.mint1].iter().zip(&mints) {
        if let Some(a) = acc {
            if a.owner == TOKEN_2022 && a.data.len() > 82 {
                bail!("mint {m} has Token-2022 extensions; drills need pools of plain mints (pick another --pool)");
            }
        }
    }
    let reserve_in = mints[2].as_ref().and_then(|a| token_amount(&a.data)).unwrap_or(0);
    if reserve_in == 0 {
        bail!("pool has an empty input vault");
    }

    // Every case runs on one snapshot of the pool. Live pools move between
    // RPC calls, and a bound quoted on one slot can be stale on the next.
    let pinned = [keys.state, keys.vault0, keys.vault1, keys.observation, keys.amm_config, keys.mint0, keys.mint1];
    let (snapshot_slot, snap) = rpc.accounts(&pinned)?;
    let snapshot: Vec<(Pubkey, Account)> = pinned.iter().zip(snap).filter_map(|(k, a)| a.map(|a| (*k, a))).collect();
    eprintln!("[drill] pool snapshot at slot {snapshot_slot}");

    let user = det_keypair("sentinel-drill-user").pubkey();
    let (ua, ub) = (det_keypair("sentinel-drill-in").pubkey(), det_keypair("sentinel-drill-out").pubkey());
    let authority = Pubkey::find_program_address(&[b"vault_and_lp_mint_auth_seed"], &program).0;
    let overlay = |amount: u64, so: Option<Vec<u8>>| Overlay {
        accounts: snapshot.iter().cloned().chain([
            (user, Account { lamports: 10_000_000_000, data: vec![], owner: Pubkey::default(), executable: false, rent_epoch: 0 }),
            (ua, token_account(&keys.mint0, &user, &keys.program0, amount)),
            (ub, token_account(&keys.mint1, &user, &keys.program1, 0)),
        ]).collect(),
        program: so.map(|b| (program, b)),
    };
    let swap = |amount: u64, min_out: u64| {
        AnchorIx::new(program, "swap_base_input")
            .u64(amount)
            .u64(min_out)
            .signer(user)
            .readonly(authority)
            .readonly(keys.amm_config)
            .mutable(keys.state)
            .mutable(ua)
            .mutable(ub)
            .mutable(keys.vault0)
            .mutable(keys.vault1)
            .readonly(keys.program0)
            .readonly(keys.program1)
            .readonly(keys.mint0)
            .readonly(keys.mint1)
            .mutable(keys.observation)
            .build()
    };
    // What the pool pays out right now for `amount`, from an unbounded run.
    let quote = |amount: u64| -> Result<u64> {
        let t = tx(&[swap(amount, 0)], &user);
        let mut fork = Fork::build(rpc, &t, &[], &overlay(amount, None))?;
        let sim = fork.simulate(&t);
        if !sim.ok {
            bail!("quote failed: {:?} {}", sim.error, fuzzforge_scenarios::invariants::summarize_logs(&sim.logs));
        }
        Ok(fork.post(&ub).and_then(|a| token_amount(&a.data)).unwrap_or(0))
    };

    let small = (reserve_in / 1_000).max(1);
    let whale = reserve_in / 2;
    let q_small = quote(small)?;
    let q_whale = quote(whale)?;
    let honest = q_small - q_small / 200; // 0.5% slippage tolerance
    let memo = Instruction { program_id: MEMO_V1, accounts: vec![AccountMeta::new_readonly(user, true)], data: b"drill".to_vec() };

    let mut cases = vec![
        ("honest swap, 0.5% slippage", "allow", tx(&[swap(small, honest)], &user), None),
        ("same swap, minimum_amount_out = 0", "hold", tx(&[swap(small, 0)], &user), None),
        ("bound one unit above what the pool pays", "block", tx(&[swap(small, q_small + 1)], &user), None),
        ("swap of half the input reserve", "allow-with-alert", tx(&[swap(whale, q_whale - q_whale / 200)], &user), None),
        ("honest swap plus an unlisted program", "hold", tx(&[swap(small, honest), memo], &user), None),
    ];
    if let Some(path) = candidate_so {
        cases.push(("honest swap on a different build of the program", "hold", tx(&[swap(small, honest)], &user), Some(std::fs::read(path)?)));
    }
    let names = ["honest", "loose", "tight", "whale", "foreign", "upgrade"];
    let mut out = Vec::new();
    for (i, (name, expect, t, so)) in cases.drain(..).enumerate() {
        let amount = if names[i] == "whale" { whale } else { small };
        let decision = check_with(rpc, policy, &t, &overlay(amount, so))?;
        out.push(Case { name, expect, decision });
    }
    Ok(out)
}
