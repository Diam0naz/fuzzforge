//! The firewall: one pending transaction in, one decision out.

use crate::cpswap::{token_amount, CpIx};
use crate::protocol::{Market, Protocol, Snapshot};
use crate::fork::{invoked_programs, Fork, Overlay};
use crate::policy::{verdict, Finding, Policy};
use crate::rpc::Rpc;
use crate::rules;
use anyhow::Result;
use serde::Serialize;
use solana_pubkey::Pubkey;
use solana_transaction::versioned::VersionedTransaction;

#[derive(Serialize)]
pub struct Decision {
    pub verdict: &'static str,
    pub policy: String,
    pub policy_version: u32,
    pub policy_sha256: String,
    /// Reviewer of a valid sign-off; `None` for an unsigned or stale policy.
    pub policy_signed_off_by: Option<String>,
    pub signature: String,
    pub forked_at_slot: u64,
    pub simulated_ok: bool,
    pub simulation_error: Option<String>,
    pub compute_units: u64,
    /// SHA-256 of the protected program's deployed bytes in the fork.
    pub program_sha256: Option<String>,
    pub pools_checked: Vec<String>,
    pub findings: Vec<Finding>,
    /// Known differences between the local run and the cluster.
    pub fidelity_notes: Vec<String>,
    pub decided_at: u64,
}

fn snapshot(fork: &Fork, protocol: Protocol, m: &Market, post: bool) -> Option<Snapshot> {
    let accounts: Vec<Vec<u8>> = m
        .reads
        .iter()
        .map(|k| if post { fork.post(k).map(|a| a.data) } else { fork.pre_data(k).map(|d| d.to_vec()) })
        .collect::<Option<_>>()?;
    let refs: Vec<&[u8]> = accounts.iter().map(|d| d.as_slice()).collect();
    protocol.snapshot(&short(&m.key), &refs)
}

pub fn check(rpc: &Rpc, policy: &Policy, tx: &VersionedTransaction) -> Result<Decision> {
    check_with(rpc, policy, tx, &Overlay::default())
}

pub fn check_with(rpc: &Rpc, policy: &Policy, tx: &VersionedTransaction, overlay: &Overlay) -> Result<Decision> {
    let program = policy.program_id();
    let mut fork = Fork::build(rpc, tx, &[], overlay)?;

    // Every market of the protected program the transaction touches, directly
    // or through a router. The accounts a snapshot needs (vaults, the share
    // mint) are cloned even if the transaction omits them.
    let protocol = policy.protocol;
    let markets: Vec<Market> = fork
        .pre
        .iter()
        .filter_map(|(k, a)| a.as_ref().filter(|a| a.owner == program).and_then(|a| protocol.market(*k, &a.data)))
        .collect();
    let reads: Vec<Pubkey> = markets.iter().flat_map(|m| m.reads.clone()).collect();
    fork.add(rpc, &reads)?;
    let pre_snaps: Vec<Option<Snapshot>> = markets.iter().map(|m| snapshot(&fork, protocol, m, false)).collect();

    // Balances the slippage rule reads, before the run.
    let keys = fork.keys.clone();
    let top: Vec<(Pubkey, Vec<Pubkey>, Vec<u8>)> = tx
        .message
        .instructions()
        .iter()
        .map(|ix| (keys[ix.program_id_index as usize], ix.accounts.iter().map(|i| keys[*i as usize]).collect(), ix.data.clone()))
        .collect();
    // Slippage needs the protocol's instruction arguments; CP-Swap only so far.
    let calls: Vec<CpIx> = if protocol == Protocol::RaydiumCpSwap {
        top.iter().filter(|(p, ..)| *p == program).map(|(_, a, d)| CpIx::decode(d, a.clone())).collect()
    } else {
        Vec::new()
    };
    let balance = |fork: &Fork, k: &Pubkey, post: bool| -> Option<u64> {
        if post { token_amount(&fork.post(k)?.data) } else { token_amount(fork.pre_data(k)?) }
    };
    let user_pre: Vec<_> = calls.iter().map(|c| c.user_accounts().map(|(a, b)| (balance(&fork, &a, false), balance(&fork, &b, false)))).collect();

    let sim = fork.simulate(tx);
    let mut findings: Vec<Finding> = Vec::new();
    let r = &policy.rules;

    if !sim.ok {
        if let Some(rule) = &r.must_simulate {
            let why = fuzzforge_scenarios::invariants::summarize_logs(&sim.logs);
            findings.push(Finding { rule: "must-simulate", action: rule.action, detail: format!("transaction fails on current state: {} ({why})", sim.error.clone().unwrap_or_default()) });
        }
    }
    rules::compute(policy, sim.compute_units, &mut findings);
    let mut invoked: Vec<Pubkey> = top.iter().map(|(p, ..)| *p).collect();
    for p in invoked_programs(&sim.logs) {
        if !invoked.contains(&p) {
            invoked.push(p);
        }
    }
    rules::allowlist(policy, &invoked, &mut findings);
    if let Some(sha) = fork.program_sha256.get(&program) {
        rules::upgrade(policy, sha, &mut findings);
    }
    for (m, pre) in markets.iter().zip(&pre_snaps) {
        if let Some(post) = snapshot(&fork, protocol, m, true) {
            rules::transition(policy, protocol, &short(&m.key), pre.as_ref(), &post, &mut findings);
        }
    }
    if sim.ok {
        for (call, pre) in calls.iter().zip(&user_pre) {
            let (Some((a, b)), Some(pre)) = (call.user_accounts(), pre) else { continue };
            let post = (balance(&fork, &a, true), balance(&fork, &b, true));
            let label = format!("{} {}", call.name(), call.pool().map(|p| short(&p)).unwrap_or_default());
            rules::slippage(policy, &label, call.call, *pre, post, &mut findings);
        }
    }

    Ok(Decision {
        verdict: verdict(&findings),
        policy: policy.name.clone(),
        policy_version: policy.version,
        policy_sha256: policy.sha256.clone(),
        policy_signed_off_by: policy.signoff.as_ref().filter(|_| policy.signoff_valid).map(|s| s.reviewer.clone()),
        signature: tx.signatures.first().map(|s| s.to_string()).unwrap_or_default(),
        forked_at_slot: fork.slot,
        simulated_ok: sim.ok,
        simulation_error: sim.error,
        compute_units: sim.compute_units,
        program_sha256: fork.program_sha256.get(&program).cloned(),
        pools_checked: markets.iter().map(|m| m.key.to_string()).collect(),
        findings,
        fidelity_notes: fork.notes.clone(),
        decided_at: now(),
    })
}

pub fn short(k: &Pubkey) -> String {
    let s = k.to_string();
    format!("{}…{}", &s[..4], &s[s.len() - 4..])
}

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
