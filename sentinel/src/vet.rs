//! Vetting and sign-off: the gate between a drafted policy and an enforced one.
//!
//! Anyone can draft a policy: a person, or an agent following `AGENTS.md`.
//! The draft can only choose rules from the closed set and set their
//! parameters. `vet` then measures each rule against live evidence:
//!
//! * drills on a live market: every rule must stay quiet on the honest case,
//!   and the rule a case targets must fire on it;
//! * history: `backtest` over logged events (CP-Swap) and `watch` rounds on
//!   live state (every protocol), where every finding is a false alarm,
//!   since these are real transactions that landed.
//!
//! A hold or block rule that fires on legitimate activity, or a rule that
//! misses its own drill case, is rejected. `sign` refuses a policy with a
//! rejected or unvetted rule, and records the reviewer against the hash of
//! the vetted file, so any later edit makes the sign-off stale.

use crate::drill;
use crate::monitor::{self, WatchArgs};
use crate::policy::{content_sha256, Action, Policy};
use crate::protocol::Protocol;
use crate::rpc::Rpc;
use anyhow::{bail, Context, Result};
use serde::Serialize;
use solana_pubkey::Pubkey;
use std::collections::BTreeMap;

#[derive(Debug, Serialize)]
pub struct RuleVerdict {
    pub rule: &'static str,
    /// OK, QUIET, NOISY, REJECT or UNTESTED.
    pub verdict: &'static str,
    pub detail: String,
}

pub struct VetArgs<'a> {
    pub pools: &'a [Pubkey],
    pub rounds: u64,
    pub interval_secs: u64,
    pub backtest_limit: usize,
    pub candidate_so: Option<&'a str>,
}

/// Rules that history (watch rounds, backtests) can show firing falsely.
fn history_checks(id: &str, protocol: Protocol) -> bool {
    matches!(id, "solvency" | "share-value" | "failed-burst" | "program-upgrade") || (id == "reserve-outflow" && protocol == Protocol::RaydiumCpSwap)
}

pub fn today() -> String {
    let days = (crate::check::now() / 86_400) as i64;
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + (m <= 2) as i64;
    format!("{y:04}-{m:02}-{d:02}")
}

pub fn vet(rpc: &Rpc, path: &str, args: &VetArgs) -> Result<(Vec<RuleVerdict>, String)> {
    let policy = &Policy::load(path)?;
    let Some(first) = args.pools.first() else { bail!("vet needs at least one --pool") };
    let mut false_alarms: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    let mut positive: BTreeMap<&'static str, (bool, &'static str)> = BTreeMap::new();
    let mut basis = Vec::new();

    // 1. Drills on the first market.
    let cases = drill::drill(rpc, policy, first, args.candidate_so)?;
    for c in &cases {
        let fired: Vec<&'static str> = c.decision.findings.iter().map(|f| f.rule).collect();
        if let Some(t) = c.targets {
            positive.insert(t, (fired.contains(&t), c.name));
        }
        for r in fired.iter().filter(|r| Some(**r) != c.targets) {
            false_alarms.entry(r).or_default().push(format!("drill case \"{}\"", c.name));
        }
    }
    basis.push(format!("{} drill cases on {}", cases.len(), short(first)));

    // 2. Logged-event history (CP-Swap).
    let mut max_outflow = None;
    if policy.protocol == Protocol::RaydiumCpSwap && args.backtest_limit > 0 {
        for pool in args.pools {
            let bt = monitor::backtest(rpc, policy, pool, args.backtest_limit)?;
            for (rule, n) in &bt.fired {
                let id = static_id(rule);
                false_alarms.entry(id).or_default().push(format!("{n}× in backtest of {}", short(pool)));
            }
            if bt.burst_windows_flagged > 0 {
                false_alarms.entry("failed-burst").or_default().push(format!("{} windows in backtest of {} ({} of {} transactions failed)", bt.burst_windows_flagged, short(pool), bt.failed, bt.signatures));
            }
            max_outflow = max_outflow.max(Some(bt.max_outflow_bps));
            basis.push(format!("backtest of {} ({} signatures, slots {}-{})", short(pool), bt.signatures, bt.first_slot, bt.last_slot));
        }
    }

    // 3. Live state, every protocol.
    if args.rounds > 0 {
        let mut buf: Vec<u8> = Vec::new();
        monitor::watch(rpc, policy, WatchArgs { pools: args.pools, interval_secs: args.interval_secs, rounds: Some(args.rounds), max_tx_per_round: 25 }, &mut buf)?;
        for line in String::from_utf8_lossy(&buf).lines() {
            let v: serde_json::Value = serde_json::from_str(line)?;
            let id = static_id(v["rule"].as_str().unwrap_or(""));
            false_alarms.entry(id).or_default().push(format!("watch: {}", v["detail"].as_str().unwrap_or("")));
        }
        basis.push(format!("{} watch rounds on {} markets", args.rounds, args.pools.len()));
    }

    // An honest drill case runs every firewall rule on legitimate input.
    let honest_case = cases.iter().any(|c| c.targets.is_none());
    let date = today();
    let basis = basis.join("; ");
    let mut verdicts = Vec::new();
    for r in policy.describe() {
        let alarms = false_alarms.get(r.id).map(|v| v.as_slice()).unwrap_or(&[]);
        let measured_history = history_checks(r.id, policy.protocol) || (honest_case && r.id != "failed-burst");
        let (verdict, mut detail) = match (positive.get(r.id), alarms.len()) {
            (Some((false, case)), _) => ("REJECT", format!("did not fire on its drill case \"{case}\"")),
            (_, n) if n > 0 && r.action != Action::Alert => ("REJECT", format!("a {:?} rule fired on legitimate activity: {}", r.action, alarms.join("; ")).to_lowercase()),
            (_, n) if n > 0 => ("NOISY", format!("fired on legitimate activity: {}", alarms.join("; "))),
            (Some((true, case)), _) => ("OK", format!("quiet on legitimate activity, fired on drill case \"{case}\"")),
            (None, _) if measured_history => ("QUIET", format!("quiet on legitimate activity; nothing in this vet makes it fire, so its positive evidence must come from {}", positive_source(r.id))),
            (None, _) => ("UNTESTED", "nothing in this vet exercises it".to_string()),
        };
        if r.id == "reserve-outflow" {
            if let Some(m) = max_outflow {
                detail.push_str(&format!("; largest legitimate single-instruction outflow seen: {m} bps"));
            }
        }
        verdicts.push(RuleVerdict { rule: r.id, verdict, detail });
    }

    // Rewrite the policy with `vetted` lines; comments and order survive.
    let text = std::fs::read_to_string(path)?;
    let mut doc: toml_edit::DocumentMut = text.parse().context("policy is not valid TOML")?;
    doc.remove("signoff");
    for v in &verdicts {
        doc["rules"][v.rule]["vetted"] = toml_edit::value(format!("{date} {}: {} [basis: {basis}]", v.verdict, v.detail));
    }
    Ok((verdicts, doc.to_string()))
}

fn positive_source(id: &str) -> &'static str {
    match id {
        "program-upgrade" => "a drill with --candidate-so <other build>",
        "failed-burst" => "observed probing traffic",
        _ => "a fuzz campaign's planted-fault canary",
    }
}

fn static_id(rule: &str) -> &'static str {
    const IDS: [&str; 9] = ["solvency", "share-value", "must-simulate", "reserve-outflow", "slippage-headroom", "program-allowlist", "program-upgrade", "compute-budget", "failed-burst"];
    IDS.iter().find(|i| **i == rule).copied().unwrap_or("unknown")
}

fn short(k: &Pubkey) -> String {
    crate::check::short(k)
}

/// Append a sign-off to a vetted policy. Refuses rejected or unvetted rules,
/// and UNTESTED ones unless `accept_untested`.
pub fn sign(path: &str, reviewer: &str, accept_untested: bool) -> Result<String> {
    let policy = Policy::load(path)?;
    let mut problems = Vec::new();
    for r in policy.describe() {
        match r.vetted {
            None => problems.push(format!("{} has not been vetted", r.id)),
            Some(v) if v.contains(" REJECT:") => problems.push(format!("{} was rejected: {v}", r.id)),
            Some(v) if v.contains(" UNTESTED:") && !accept_untested => problems.push(format!("{} is untested (pass --accept-untested to sign anyway)", r.id)),
            _ => {}
        }
    }
    if !problems.is_empty() {
        bail!("not signing:\n  {}", problems.join("\n  "));
    }
    let text = std::fs::read_to_string(path)?;
    let body = match text.find("\n[signoff]") {
        Some(i) => text[..i + 1].to_string(),
        None => format!("{}\n\n", text.trim_end()),
    };
    let signed = format!(
        "{body}[signoff]\nreviewer = {}\ndate = \"{}\"\nrules_sha256 = \"{}\"\n",
        toml_edit::value(reviewer).to_string().trim(),
        today(),
        content_sha256(&body)
    );
    let check = Policy::parse(&signed)?;
    if !check.signoff_valid {
        bail!("internal error: fresh sign-off does not verify");
    }
    Ok(signed)
}
