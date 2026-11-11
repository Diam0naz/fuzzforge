//! The firewall: one pending transaction in, one decision out.

use crate::cpswap::{token_amount, CpIx, PoolKeys, PoolView};
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

fn view(fork: &Fork, pool: &PoolKeys, post: bool) -> Option<PoolView> {
    if post {
        let (p, a, b) = (fork.post(&pool.state)?, fork.post(&pool.vault0)?, fork.post(&pool.vault1)?);
        PoolView::decode(&p.data, &a.data, &b.data)
    } else {
        PoolView::decode(fork.pre_data(&pool.state)?, fork.pre_data(&pool.vault0)?, fork.pre_data(&pool.vault1)?)
    }
}

pub fn check(rpc: &Rpc, policy: &Policy, tx: &VersionedTransaction) -> Result<Decision> {
    check_with(rpc, policy, tx, &Overlay::default())
}

pub fn check_with(rpc: &Rpc, policy: &Policy, tx: &VersionedTransaction, overlay: &Overlay) -> Result<Decision> {
    let program = policy.program_id();
    let mut fork = Fork::build(rpc, tx, &[], overlay)?;

    // Every pool of the protected program the transaction touches, directly
    // or through a router. Their vaults are cloned even if the tx omits them.
    let pools: Vec<PoolKeys> = fork
        .pre
        .iter()
        .filter_map(|(k, a)| a.as_ref().filter(|a| a.owner == program).and_then(|a| PoolKeys::decode(*k, &a.data)))
        .collect();
    let vaults: Vec<Pubkey> = pools.iter().flat_map(|p| [p.vault0, p.vault1]).collect();
    fork.add(rpc, &vaults)?;
    let pre_views: Vec<Option<PoolView>> = pools.iter().map(|p| view(&fork, p, false)).collect();

    // Balances the slippage rule reads, before the run.
    let keys = fork.keys.clone();
    let top: Vec<(Pubkey, Vec<Pubkey>, Vec<u8>)> = tx
        .message
        .instructions()
        .iter()
        .map(|ix| (keys[ix.program_id_index as usize], ix.accounts.iter().map(|i| keys[*i as usize]).collect(), ix.data.clone()))
        .collect();
    let calls: Vec<CpIx> = top.iter().filter(|(p, ..)| *p == program).map(|(_, a, d)| CpIx::decode(d, a.clone())).collect();
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
    for (pool, pre) in pools.iter().zip(&pre_views) {
        if let Some(post) = view(&fork, pool, true) {
            rules::pool_transition(policy, &short(&pool.state), *pre, post, &mut findings);
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
        signature: tx.signatures.first().map(|s| s.to_string()).unwrap_or_default(),
        forked_at_slot: fork.slot,
        simulated_ok: sim.ok,
        simulation_error: sim.error,
        compute_units: sim.compute_units,
        program_sha256: fork.program_sha256.get(&program).cloned(),
        pools_checked: pools.iter().map(|p| p.state.to_string()).collect(),
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
