//! The policy file: every intervention the monitor or firewall can make is a
//! named rule in one TOML document that a person reviews and signs off.
//!
//! The set of rules is closed. A rule the engine does not implement, a
//! misspelled id or an unknown field fails the load, so a policy can never
//! list a protection that is not enforced. Every decision record carries the
//! SHA-256 of the policy that produced it.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_pubkey::Pubkey;
use std::str::FromStr;

/// What happens when a rule fires, in increasing severity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Record it and carry on.
    Alert,
    /// Do not sign or proceed until a person approves.
    Hold,
    /// Refuse.
    Block,
}

/// Fields every rule carries. `why` is for the reviewer; `evidence` says how
/// the rule was validated (fuzz campaign, backtest), so its false-alarm rate
/// is a number rather than a hope.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Basic {
    pub action: Action,
    pub why: String,
    pub evidence: Option<String>,
    /// Written by `sentinel vet`: what drills and history measured.
    pub vetted: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bps {
    pub action: Action,
    pub max_bps: u64,
    pub why: String,
    pub evidence: Option<String>,
    /// Written by `sentinel vet`: what drills and history measured.
    pub vetted: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Units {
    pub action: Action,
    pub max_units: u64,
    pub why: String,
    pub evidence: Option<String>,
    /// Written by `sentinel vet`: what drills and history measured.
    pub vetted: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allowlist {
    pub action: Action,
    pub programs: Vec<String>,
    pub why: String,
    pub evidence: Option<String>,
    /// Written by `sentinel vet`: what drills and history measured.
    pub vetted: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    pub action: Action,
    /// SHA-256 of the deployed program's ELF (what `solana program dump` writes).
    pub sha256: String,
    pub why: String,
    pub evidence: Option<String>,
    /// Written by `sentinel vet`: what drills and history measured.
    pub vetted: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Burst {
    pub action: Action,
    /// Look at this many most recent transactions…
    pub window: usize,
    /// …and fire when more than this many of them failed.
    pub max_failed: usize,
    pub why: String,
    pub evidence: Option<String>,
    /// Written by `sentinel vet`: what drills and history measured.
    pub vetted: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Rules {
    pub solvency: Option<Basic>,
    pub share_value: Option<Basic>,
    pub reserve_outflow: Option<Bps>,
    pub slippage_headroom: Option<Bps>,
    pub program_allowlist: Option<Allowlist>,
    pub program_upgrade: Option<Pin>,
    pub compute_budget: Option<Units>,
    pub must_simulate: Option<Basic>,
    pub failed_burst: Option<Burst>,
    /// Early warning: a pool's total reserves fell more than `max_bps` between
    /// monitor rounds. Catches a drain or a run spread across many
    /// transactions, which the per-instruction `reserve-outflow` rule misses.
    pub reserve_drop: Option<Bps>,
    /// Early warning: a program outside `program_allowlist` appears in a pool's
    /// recent transactions (an unexpected integrator or an abnormal CPI).
    /// Requires `program_allowlist` to be set.
    pub foreign_cpi: Option<Basic>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub name: String,
    pub version: u32,
    /// Which adapter reads the protected program's accounts.
    pub protocol: crate::protocol::Protocol,
    /// The program these rules protect.
    pub program: String,
    pub rules: Rules,
    /// Who or what drafted the rules (a person, or an agent and its model).
    pub drafted_by: Option<String>,
    /// Added by `sentinel sign`; must stay the last table in the file.
    pub signoff: Option<Signoff>,
    #[serde(skip)]
    pub sha256: String,
    /// The sign-off's hash matches the file as it is now.
    #[serde(skip)]
    pub signoff_valid: bool,
    #[serde(skip)]
    pub allowed: Vec<Pubkey>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signoff {
    pub reviewer: String,
    pub date: String,
    /// SHA-256 of the file up to the `[signoff]` line.
    pub rules_sha256: String,
}

/// SHA-256 of a policy file's text before its `[signoff]` table.
pub fn content_sha256(text: &str) -> String {
    let body = match text.find("\n[signoff]") {
        Some(i) => &text[..i + 1],
        None => text,
    };
    hex(&Sha256::digest(body.as_bytes()))
}

/// One rule firing.
#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub rule: &'static str,
    pub action: Action,
    pub detail: String,
}

impl Policy {
    pub fn load(path: &str) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading policy {path}"))?;
        Self::parse(&text).with_context(|| format!("policy {path}"))
    }

    pub fn parse(text: &str) -> Result<Self> {
        let mut policy: Policy = toml::from_str(text)?;
        policy.sha256 = hex(&Sha256::digest(text.as_bytes()));
        policy.signoff_valid = policy.signoff.as_ref().is_some_and(|so| so.rules_sha256 == content_sha256(text));
        Pubkey::from_str(&policy.program).context("`program` is not a public key")?;
        if let Some(rule) = &policy.rules.program_allowlist {
            for p in &rule.programs {
                // Entries may carry a trailing comment-like label after whitespace.
                let key = p.split_whitespace().next().unwrap_or("");
                policy.allowed.push(Pubkey::from_str(key).with_context(|| format!("allowlist entry `{p}`"))?);
            }
        }
        Ok(policy)
    }

    pub fn program_id(&self) -> Pubkey {
        Pubkey::from_str(&self.program).expect("validated at load")
    }

    /// One entry per rule present, for review, vetting and signing.
    pub fn describe(&self) -> Vec<RuleInfo<'_>> {
        let r = &self.rules;
        let mut out = Vec::new();
        macro_rules! info {
            ($id:expr, $rule:expr, $param:expr) => {
                if let Some(b) = $rule {
                    out.push(RuleInfo { id: $id, action: b.action, param: $param(b), why: &b.why, evidence: b.evidence.as_deref(), vetted: b.vetted.as_deref() });
                }
            };
        }
        let none = |_: &Basic| String::new();
        info!("solvency", &r.solvency, none);
        info!("share-value", &r.share_value, none);
        info!("must-simulate", &r.must_simulate, none);
        info!("reserve-outflow", &r.reserve_outflow, |b: &Bps| format!("max {} bps", b.max_bps));
        info!("slippage-headroom", &r.slippage_headroom, |b: &Bps| format!("max {} bps", b.max_bps));
        info!("program-allowlist", &r.program_allowlist, |b: &Allowlist| format!("{} programs", b.programs.len()));
        info!("program-upgrade", &r.program_upgrade, |b: &Pin| format!("sha256 {}…", &b.sha256[..b.sha256.len().min(12)]));
        info!("compute-budget", &r.compute_budget, |b: &Units| format!("max {} units", b.max_units));
        info!("failed-burst", &r.failed_burst, |b: &Burst| format!("more than {} of last {}", b.max_failed, b.window));
        info!("reserve-drop", &r.reserve_drop, |b: &Bps| format!("max {} bps between rounds", b.max_bps));
        info!("foreign-cpi", &r.foreign_cpi, |_: &Basic| String::new());
        out
    }
}

pub struct RuleInfo<'a> {
    pub id: &'static str,
    pub action: Action,
    pub param: String,
    pub why: &'a str,
    pub evidence: Option<&'a str>,
    pub vetted: Option<&'a str>,
}

/// The decision a set of findings adds up to: the most severe action wins.
pub fn verdict(findings: &[Finding]) -> &'static str {
    match findings.iter().map(|f| f.action).max() {
        None => "allow",
        Some(Action::Alert) => "allow-with-alert",
        Some(Action::Hold) => "hold",
        Some(Action::Block) => "block",
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
