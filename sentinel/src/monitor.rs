//! Continuous monitoring and backtesting against live chain data.
//!
//! `watch` re-reads each pool's state every round (pool and both vaults in one
//! `getMultipleAccounts`, so the three are from the same slot), checks
//! solvency and share value against the previous round, scans the pool's new
//! transactions for large reserve outflows and bursts of failures, and checks
//! the program's deployed bytes against the pinned hash.
//!
//! `backtest` runs the event-based rules over a pool's recent history. Its
//! counts are the false-alarm evidence a policy reviewer signs off on.

use crate::check::{now, short};
use crate::cpswap::{events, Event, PoolKeys, PoolView};
use crate::policy::{Finding, Policy};
use crate::rpc::{Rpc, SigInfo};
use crate::rules;
use anyhow::{anyhow, Context, Result};
use fuzzforge_scenarios::invariants::share_value_fell;
use serde_json::json;
use sha2::{Digest, Sha256};
use solana_pubkey::Pubkey;
use std::collections::{BTreeMap, HashSet};
use std::io::Write;

pub fn load_pools(rpc: &Rpc, program: &Pubkey, pools: &[Pubkey]) -> Result<Vec<PoolKeys>> {
    let (_, accounts) = rpc.accounts(pools)?;
    pools
        .iter()
        .zip(accounts)
        .map(|(k, a)| {
            let a = a.ok_or_else(|| anyhow!("pool {k} does not exist"))?;
            if a.owner != *program {
                return Err(anyhow!("{k} is owned by {}, not {program}", a.owner));
            }
            PoolKeys::decode(*k, &a.data).ok_or_else(|| anyhow!("{k} is not a CP-Swap pool"))
        })
        .collect()
}

fn programdata_address(rpc: &Rpc, program: &Pubkey) -> Result<Pubkey> {
    let d = rpc.account_prefix(program, 36)?.ok_or_else(|| anyhow!("program {program} not found"))?;
    Ok(Pubkey::new_from_array(d.get(4..36).ok_or_else(|| anyhow!("{program} is not an upgradeable program"))?.try_into()?))
}

fn deploy_slot(rpc: &Rpc, programdata: &Pubkey) -> Result<u64> {
    let d = rpc.account_prefix(programdata, 12)?.ok_or_else(|| anyhow!("programdata missing"))?;
    Ok(u64::from_le_bytes(d[4..12].try_into()?))
}

fn deployed_sha256(rpc: &Rpc, programdata: &Pubkey) -> Result<String> {
    let (_, a) = rpc.accounts(&[*programdata])?;
    let a = a.into_iter().next().flatten().ok_or_else(|| anyhow!("programdata missing"))?;
    Ok(crate::policy::hex(&Sha256::digest(&a.data[45.min(a.data.len())..])))
}

/// Chronological order: slot, then position in the block.
fn chronological(mut sigs: Vec<SigInfo>) -> Vec<SigInfo> {
    sigs.reverse();
    sigs.sort_by_key(|s| (s.slot, s.index.unwrap_or(0)));
    sigs
}

pub struct WatchArgs<'a> {
    pub pools: &'a [Pubkey],
    pub interval_secs: u64,
    pub rounds: Option<u64>,
    pub max_tx_per_round: usize,
}

pub fn watch(rpc: &Rpc, policy: &Policy, args: WatchArgs, out: &mut dyn Write) -> Result<()> {
    let program = policy.program_id();
    let pools = load_pools(rpc, &program, args.pools)?;
    let programdata = programdata_address(rpc, &program)?;
    let mut known_deploy = deploy_slot(rpc, &programdata)?;
    let mut first: Vec<Finding> = Vec::new();
    rules::upgrade(policy, &deployed_sha256(rpc, &programdata)?, &mut first);

    let mut last_view: Vec<Option<PoolView>> = vec![None; pools.len()];
    let mut last_sig: Vec<Option<String>> = vec![None; pools.len()];
    let mut recent: Vec<Vec<bool>> = vec![Vec::new(); pools.len()];
    let mut firing: HashSet<(usize, &'static str)> = HashSet::new();
    let emit = |out: &mut dyn Write, slot: u64, pool: Option<&Pubkey>, sig: Option<&str>, f: &Finding| -> Result<()> {
        let rec = json!({
            "at": now(), "slot": slot, "pool": pool.map(|p| p.to_string()), "signature": sig,
            "rule": f.rule, "action": f.action, "detail": f.detail,
            "policy": policy.name, "policy_sha256": policy.sha256,
        });
        writeln!(out, "{rec}")?;
        out.flush()?;
        Ok(())
    };
    for f in &first {
        emit(out, 0, None, None, f)?;
    }

    let mut round = 0u64;
    loop {
        round += 1;
        let (mut n_tx, mut n_alerts) = (0usize, 0usize);
        let keys: Vec<Pubkey> = pools.iter().flat_map(|p| [p.state, p.vault0, p.vault1]).collect();
        let (slot, accounts) = rpc.accounts(&keys)?;
        for (i, pool) in pools.iter().enumerate() {
            let label = short(&pool.state);
            let (p, a, b) = (&accounts[3 * i], &accounts[3 * i + 1], &accounts[3 * i + 2]);
            let mut found = Vec::new();
            if let (Some(p), Some(a), Some(b)) = (p, a, b) {
                if let Some(now_view) = PoolView::decode(&p.data, &a.data, &b.data) {
                    // Reserve outflow between rounds aggregates many trades; the
                    // per-instruction check below is the meaningful one.
                    let mut state_findings = Vec::new();
                    rules::pool_transition(policy, &label, last_view[i], now_view, &mut state_findings);
                    found.extend(state_findings.into_iter().filter(|f| f.rule != "reserve-outflow"));
                    last_view[i] = Some(now_view);
                }
            }

            let limit = if last_sig[i].is_none() { 20 } else { 100 };
            let sigs = chronological(rpc.signatures(&pool.state, limit, last_sig[i].as_deref(), None)?);
            if let Some(newest) = sigs.last() {
                last_sig[i] = Some(newest.signature.clone());
            }
            for s in &sigs {
                recent[i].push(s.failed);
            }
            let keep = policy.rules.failed_burst.as_ref().map(|b| b.window).unwrap_or(0).max(1);
            let excess = recent[i].len().saturating_sub(keep);
            recent[i].drain(..excess);
            rules::burst(policy, &label, &recent[i], &mut found);

            for s in sigs.iter().filter(|s| !s.failed).rev().take(args.max_tx_per_round) {
                let Some(tx) = rpc.transaction(&s.signature)? else { continue };
                n_tx += 1;
                let (evs, _) = events(&program, &tx.logs);
                let mut tx_findings = Vec::new();
                for ev in evs.iter().filter(|e| e.pool() == pool.state) {
                    rules::event_outflow(policy, &label, ev, &mut tx_findings);
                }
                for f in &tx_findings {
                    emit(out, tx.slot, Some(&pool.state), Some(&s.signature), f)?;
                    n_alerts += 1;
                }
            }

            // Persistent conditions (insolvent, in a failure burst) are
            // reported when they start, not every round.
            let now_firing: HashSet<&'static str> = found.iter().map(|f| f.rule).collect();
            for f in &found {
                if f.rule == "share-value" || !firing.contains(&(i, f.rule)) {
                    emit(out, slot, Some(&pool.state), None, f)?;
                    n_alerts += 1;
                }
            }
            firing.retain(|(j, r)| *j != i || now_firing.contains(r));
            firing.extend(now_firing.into_iter().map(|r| (i, r)));
        }

        let deploy = deploy_slot(rpc, &programdata)?;
        if deploy != known_deploy {
            let mut f = Vec::new();
            rules::upgrade(policy, &deployed_sha256(rpc, &programdata)?, &mut f);
            if f.is_empty() {
                f.push(Finding { rule: "program-upgrade", action: crate::policy::Action::Alert, detail: format!("program redeployed at slot {deploy}; bytes match the pin") });
            }
            for x in &f {
                emit(out, slot, None, None, x)?;
                n_alerts += 1;
            }
            known_deploy = deploy;
        }

        eprintln!("[sentinel] round {round} slot {slot}: {} pools, {n_tx} transactions read, {n_alerts} findings", pools.len());
        if args.rounds.is_some_and(|r| round >= r) {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_secs(args.interval_secs));
    }
}

#[derive(Default, serde::Serialize)]
pub struct Backtest {
    pub pool: String,
    pub first_slot: u64,
    pub last_slot: u64,
    pub signatures: usize,
    pub failed: usize,
    pub transactions_read: usize,
    pub swap_events: usize,
    pub lp_events: usize,
    pub share_value_comparisons: usize,
    pub burst_windows_flagged: usize,
    pub fired: BTreeMap<String, usize>,
    pub examples: Vec<(String, Finding)>,
}

pub fn backtest(rpc: &Rpc, policy: &Policy, pool: &Pubkey, limit: usize) -> Result<Backtest> {
    let program = policy.program_id();
    let keys = load_pools(rpc, &program, &[*pool])?.remove(0);
    let label = short(pool);

    let mut sigs = Vec::new();
    let mut before: Option<String> = None;
    while sigs.len() < limit {
        let page = rpc.signatures(pool, (limit - sigs.len()).min(1000), None, before.as_deref())?;
        let Some(last) = page.last() else { break };
        before = Some(last.signature.clone());
        sigs.extend(page);
    }
    let sigs = chronological(sigs);
    let mut bt = Backtest { pool: pool.to_string(), signatures: sigs.len(), ..Default::default() };
    bt.first_slot = sigs.first().map(|s| s.slot).unwrap_or(0);
    bt.last_slot = sigs.last().map(|s| s.slot).unwrap_or(0);

    let record = |bt: &mut Backtest, sig: &str, fs: Vec<Finding>| {
        for f in fs {
            *bt.fired.entry(f.rule.to_string()).or_default() += 1;
            if bt.examples.len() < 10 {
                bt.examples.push((sig.to_string(), f));
            }
        }
    };

    // Share value from event history. LP supply is constant between LP
    // events, so within a segment the rule reduces to "k never falls"; the
    // comparison is skipped across an LP change, whose after-state the events
    // do not report.
    let mut prev: Option<(u64, u64)> = None;
    let mut flags: Vec<bool> = Vec::new();
    for (n, s) in sigs.iter().enumerate() {
        flags.push(s.failed);
        let mut burst = Vec::new();
        rules::burst(policy, &label, &flags, &mut burst);
        if !burst.is_empty() {
            bt.burst_windows_flagged += 1;
        }
        if s.failed {
            bt.failed += 1;
            continue;
        }
        let tx = rpc.transaction(&s.signature).with_context(|| format!("transaction {}", s.signature))?;
        let Some(tx) = tx else { continue };
        bt.transactions_read += 1;
        let (evs, _) = events(&program, &tx.logs);
        let mut found = Vec::new();
        for ev in evs.iter().filter(|e| e.pool() == *pool) {
            rules::event_outflow(policy, &label, ev, &mut found);
            let (now, ends_segment) = match *ev {
                Event::Swap { input_before, output_before, input_mint, .. } => {
                    bt.swap_events += 1;
                    (if input_mint == keys.mint0 { (input_before, output_before) } else { (output_before, input_before) }, false)
                }
                Event::Lp { r0_before, r1_before, .. } => {
                    bt.lp_events += 1;
                    ((r0_before, r1_before), true)
                }
            };
            if let (Some(p), Some(rule)) = (prev, &policy.rules.share_value) {
                bt.share_value_comparisons += 1;
                if share_value_fell((p.0, p.1, 1), (now.0, now.1, 1)) {
                    found.push(Finding { rule: "share-value", action: rule.action, detail: format!("{label}: reserves ({}, {}) -> ({}, {}) with no LP change in between", p.0, p.1, now.0, now.1) });
                }
            }
            prev = if ends_segment { None } else { Some(now) };
        }
        record(&mut bt, &s.signature, found);
        if (n + 1) % 50 == 0 {
            eprintln!("[sentinel] backtest {}/{}", n + 1, sigs.len());
        }
    }
    Ok(bt)
}
