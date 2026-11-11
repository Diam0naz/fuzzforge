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
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bps {
    pub action: Action,
    pub max_bps: u64,
    pub why: String,
    pub evidence: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Units {
    pub action: Action,
    pub max_units: u64,
    pub why: String,
    pub evidence: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allowlist {
    pub action: Action,
    pub programs: Vec<String>,
    pub why: String,
    pub evidence: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    pub action: Action,
    /// SHA-256 of the deployed program's ELF (what `solana program dump` writes).
    pub sha256: String,
    pub why: String,
    pub evidence: Option<String>,
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
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub name: String,
    pub version: u32,
    /// The program these rules protect.
    pub program: String,
    pub rules: Rules,
    #[serde(skip)]
    pub sha256: String,
    #[serde(skip)]
    pub allowed: Vec<Pubkey>,
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

    /// One line per rule, for `sentinel policy` and for review.
    pub fn describe(&self) -> Vec<(&'static str, Action, String, &str, Option<&str>)> {
        let r = &self.rules;
        let mut out = Vec::new();
        for (id, rule) in [("solvency", &r.solvency), ("share-value", &r.share_value), ("must-simulate", &r.must_simulate)] {
            if let Some(b) = rule {
                out.push((id, b.action, String::new(), b.why.as_str(), b.evidence.as_deref()));
            }
        }
        for (id, rule) in [("reserve-outflow", &r.reserve_outflow), ("slippage-headroom", &r.slippage_headroom)] {
            if let Some(b) = rule {
                out.push((id, b.action, format!("max {} bps", b.max_bps), b.why.as_str(), b.evidence.as_deref()));
            }
        }
        if let Some(b) = &r.program_allowlist {
            out.push(("program-allowlist", b.action, format!("{} programs", b.programs.len()), b.why.as_str(), b.evidence.as_deref()));
        }
        if let Some(b) = &r.program_upgrade {
            out.push(("program-upgrade", b.action, format!("sha256 {}…", &b.sha256[..b.sha256.len().min(12)]), b.why.as_str(), b.evidence.as_deref()));
        }
        if let Some(b) = &r.compute_budget {
            out.push(("compute-budget", b.action, format!("max {} units", b.max_units), b.why.as_str(), b.evidence.as_deref()));
        }
        if let Some(b) = &r.failed_burst {
            out.push(("failed-burst", b.action, format!("more than {} of last {}", b.max_failed, b.window), b.why.as_str(), b.evidence.as_deref()));
        }
        out
    }
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
