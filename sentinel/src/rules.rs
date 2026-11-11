//! Rule evaluation. Each function applies one policy rule and pushes a
//! [`Finding`] when it fires; rules missing from the policy are skipped.
//!
//! The predicates are the ones the fuzz campaigns asserted:
//! `fuzzforge_scenarios::invariants::{solvency, share_value_fell}` are called
//! here unchanged, and the slippage rule measures on the user's own token
//! accounts exactly as the CP-Swap harness does.

use crate::cpswap::{Call, Event, PoolView};
use crate::policy::{Finding, Policy};
use fuzzforge_scenarios::invariants::{share_value_fell, solvency};
use solana_pubkey::Pubkey;

pub type Findings = Vec<Finding>;

/// Basis points of `before` that `removed` represents, rounded down.
pub fn bps(removed: u64, before: u64) -> u64 {
    if before == 0 {
        return if removed == 0 { 0 } else { 10_000 };
    }
    (removed as u128 * 10_000 / before as u128) as u64
}

/// Solvency of `post`, plus share value and reserve outflow from `pre` to
/// `post` when the earlier state is known.
pub fn pool_transition(policy: &Policy, label: &str, pre: Option<PoolView>, post: PoolView, out: &mut Findings) {
    let r = &policy.rules;
    if let Some(rule) = &r.solvency {
        if let Some(msg) = solvency(label, (post.vault0, post.vault1), (post.fees0, post.fees1)) {
            out.push(Finding { rule: "solvency", action: rule.action, detail: msg });
        }
    }
    let Some(pre) = pre else { return };
    if let Some(rule) = &r.share_value {
        if share_value_fell(pre.state(), post.state()) {
            let ((a, b, c), (x, y, z)) = (pre.state(), post.state());
            out.push(Finding {
                rule: "share-value",
                action: rule.action,
                detail: format!("{label}: LP share value fell: reserves ({a}, {b}) / lp {c} -> ({x}, {y}) / lp {z}"),
            });
        }
    }
    if let Some(rule) = &r.reserve_outflow {
        let ((a, b), (x, y)) = (pre.reserves(), post.reserves());
        for (side, before, after) in [(0, a, x), (1, b, y)] {
            let moved = bps(before.saturating_sub(after), before);
            if moved > rule.max_bps {
                out.push(Finding {
                    rule: "reserve-outflow",
                    action: rule.action,
                    detail: format!("{label}: reserve {side} fell {before} -> {after} ({moved} bps in one step, limit {})", rule.max_bps),
                });
            }
        }
    }
}

/// Reserve outflow as reported by one logged event (monitor and backtest).
pub fn event_outflow(policy: &Policy, label: &str, ev: &Event, out: &mut Findings) {
    let Some(rule) = &policy.rules.reserve_outflow else { return };
    let legs: Vec<(u64, u64)> = match *ev {
        Event::Swap { output_before, output_amount, .. } => vec![(output_amount, output_before)],
        Event::Lp { withdraw: true, amount0, amount1, r0_before, r1_before, .. } => vec![(amount0, r0_before), (amount1, r1_before)],
        Event::Lp { .. } => vec![],
    };
    for (removed, before) in legs {
        let moved = bps(removed, before);
        if moved > rule.max_bps {
            out.push(Finding {
                rule: "reserve-outflow",
                action: rule.action,
                detail: format!("{label}: one instruction took {removed} of a {before} reserve ({moved} bps, limit {})", rule.max_bps),
            });
        }
    }
}

/// Slippage measured on what arrives. `pre`/`post` are the balances of the
/// instruction's two user token accounts (see `CpIx::user_accounts`).
///
/// Two findings are possible. A signed bound that the outcome breaks is the
/// fuzzed slippage invariant failing, so it always blocks. A bound looser
/// than `max_bps` beyond the simulated outcome is what a sandwich bot needs;
/// that one takes the rule's own action.
pub fn slippage(policy: &Policy, label: &str, call: Call, pre: (Option<u64>, Option<u64>), post: (Option<u64>, Option<u64>), out: &mut Findings) {
    let Some(rule) = &policy.rules.slippage_headroom else { return };
    let delta_in = |pre: Option<u64>, post: Option<u64>| Some(post?.checked_sub(pre?).unwrap_or(0));
    let delta_out = |pre: Option<u64>, post: Option<u64>| Some(pre?.checked_sub(post?).unwrap_or(0));
    // (what the user signed, what happened, true when the bound is a minimum)
    let legs: Vec<(&str, u64, Option<u64>, bool)> = match call {
        Call::SwapIn { min_out, .. } => vec![("received", min_out, delta_in(pre.1, post.1), true)],
        Call::SwapOut { max_in, .. } => vec![("paid", max_in, delta_out(pre.0, post.0), false)],
        Call::Deposit { max0, max1, .. } => vec![("paid token 0", max0, delta_out(pre.0, post.0), false), ("paid token 1", max1, delta_out(pre.1, post.1), false)],
        Call::Withdraw { min0, min1, .. } => vec![("received token 0", min0, delta_in(pre.0, post.0), true), ("received token 1", min1, delta_in(pre.1, post.1), true)],
        _ => vec![],
    };
    for (what, bound, actual, is_min) in legs {
        let Some(actual) = actual else { continue };
        let broken = if is_min { actual < bound } else { actual > bound };
        if broken {
            out.push(Finding {
                rule: "slippage-headroom",
                action: crate::policy::Action::Block,
                detail: format!("{label}: user {what} {actual} but signed a bound of {bound}: the program broke the user's limit"),
            });
            continue;
        }
        let slack = if is_min { bps(actual - bound, actual) } else { bps(bound - actual, actual.max(1)) };
        if slack > rule.max_bps {
            out.push(Finding {
                rule: "slippage-headroom",
                action: rule.action,
                detail: format!("{label}: user {what} {actual} with a signed bound of {bound}: {slack} bps of room for a sandwich (limit {})", rule.max_bps),
            });
        }
    }
}

pub fn allowlist(policy: &Policy, invoked: &[Pubkey], out: &mut Findings) {
    let Some(rule) = &policy.rules.program_allowlist else { return };
    for p in invoked {
        if !policy.allowed.contains(p) {
            out.push(Finding { rule: "program-allowlist", action: rule.action, detail: format!("transaction invokes {p}, which the policy does not list") });
        }
    }
}

pub fn compute(policy: &Policy, units: u64, out: &mut Findings) {
    let Some(rule) = &policy.rules.compute_budget else { return };
    if units > rule.max_units {
        out.push(Finding { rule: "compute-budget", action: rule.action, detail: format!("used {units} compute units, limit {}", rule.max_units) });
    }
}

pub fn upgrade(policy: &Policy, deployed_sha256: &str, out: &mut Findings) {
    let Some(rule) = &policy.rules.program_upgrade else { return };
    if !deployed_sha256.eq_ignore_ascii_case(&rule.sha256) {
        out.push(Finding {
            rule: "program-upgrade",
            action: rule.action,
            detail: format!("deployed program is {deployed_sha256}, policy pins {}: re-run the upgrade-diff campaign before trusting it", rule.sha256),
        });
    }
}

/// `recent` holds failure flags of the most recent transactions, newest last.
pub fn burst(policy: &Policy, label: &str, recent: &[bool], out: &mut Findings) {
    let Some(rule) = &policy.rules.failed_burst else { return };
    if recent.len() < rule.window {
        return;
    }
    let failed = recent[recent.len() - rule.window..].iter().filter(|f| **f).count();
    if failed > rule.max_failed {
        out.push(Finding {
            rule: "failed-burst",
            action: rule.action,
            detail: format!("{label}: {failed} of the last {} transactions failed (limit {})", rule.window, rule.max_failed),
        });
    }
}
