//! Fund tracing for incident response.
//!
//! Start from one transaction (a monitor finding's signature, or the
//! exploit itself). Per asset, the wallets whose balance fell are sources and
//! the wallets whose balance rose are sinks; when one transaction has several
//! of each, value is split pro rata and the edge is marked `inferred`.
//! Tainted wallets' later transactions are read hop by hop, oldest first.
//!
//! Off-curve sinks (PDAs: pool vaults, program authorities) are reported and
//! not followed, since value there belongs to a program, not a person. The
//! report ends with what the traced wallets hold now, and which of those
//! mints have a freeze authority: the issuers worth contacting first.

use crate::rpc::{Rpc, TxBalances};
use anyhow::{anyhow, Result};
use serde::Serialize;
use solana_pubkey::Pubkey;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt::Write as _;
use std::str::FromStr;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Edge {
    pub signature: String,
    pub slot: u64,
    pub block_time: Option<i64>,
    pub from: String,
    pub to: String,
    pub asset: String,
    pub decimals: u8,
    pub amount: u128,
    /// Several sources and sinks of this asset in one transaction: the split
    /// between them is pro rata, not read from instructions.
    pub inferred: bool,
    pub hop: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct Node {
    pub address: String,
    pub hop: usize,
    pub first_seen_slot: u64,
    /// "seed", "wallet", or "program-owned" (off curve; not followed).
    pub kind: &'static str,
    pub label: Option<String>,
    pub transactions_read: usize,
    /// More transactions existed than `--max-tx` allowed reading.
    pub truncated: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Holding {
    pub wallet: String,
    pub token_account: String,
    pub mint: String,
    pub amount: u128,
    pub freeze_authority: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Trace {
    pub start: String,
    pub victims: Vec<String>,
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    pub holdings: Vec<Holding>,
    pub limits: String,
}

pub struct TraceArgs {
    pub signature: String,
    /// Wallets that lost funds in the start transaction. Empty: every wallet
    /// whose balance fell.
    pub victims: Vec<String>,
    pub hops: usize,
    pub max_tx_per_wallet: usize,
    pub max_nodes: usize,
    /// Ignore SOL movements below this many lamports (rent, fees).
    pub min_lamports: u128,
    pub labels: HashMap<String, String>,
}

/// Per-asset flows of one transaction, pro rata when ambiguous.
pub fn flows(tx: &TxBalances, min_lamports: u128, hop: usize) -> Vec<Edge> {
    let mut by_asset: BTreeMap<&str, (u8, BTreeMap<&str, i128>)> = BTreeMap::new();
    for b in &tx.balances {
        let e = by_asset.entry(&b.asset).or_insert((b.decimals, BTreeMap::new()));
        *e.1.entry(&b.owner).or_default() += b.post as i128 - b.pre as i128;
    }
    let mut out = Vec::new();
    for (asset, (decimals, deltas)) in by_asset {
        let floor = if asset == "SOL" { min_lamports as i128 } else { 1 };
        let sources: Vec<(&str, u128)> = deltas.iter().filter(|(_, d)| **d <= -floor).map(|(o, d)| (*o, (-d) as u128)).collect();
        let sinks: Vec<(&str, u128)> = deltas.iter().filter(|(_, d)| **d >= floor).map(|(o, d)| (*o, *d as u128)).collect();
        let total: u128 = sources.iter().map(|s| s.1).sum();
        if total == 0 {
            continue;
        }
        let inferred = sources.len() > 1 && sinks.len() > 1;
        for (to, got) in &sinks {
            for (from, sent) in &sources {
                let amount = got * sent / total;
                if amount > 0 {
                    out.push(Edge {
                        signature: tx.signature.clone(),
                        slot: tx.slot,
                        block_time: tx.block_time,
                        from: from.to_string(),
                        to: to.to_string(),
                        asset: asset.to_string(),
                        decimals,
                        amount,
                        inferred,
                        hop,
                    });
                }
            }
        }
    }
    out
}

fn off_curve(address: &str) -> bool {
    Pubkey::from_str(address).map(|k| !k.is_on_curve()).unwrap_or(false)
}

pub fn trace(rpc: &Rpc, args: &TraceArgs) -> Result<Trace> {
    let start = rpc.balances(&args.signature)?.ok_or_else(|| anyhow!("{} not found", args.signature))?;
    if start.failed {
        return Err(anyhow!("{} failed on chain and moved nothing", args.signature));
    }
    let first = flows(&start, args.min_lamports, 0);
    let victims: Vec<String> = if args.victims.is_empty() {
        let mut v: Vec<String> = first.iter().map(|e| e.from.clone()).collect();
        v.sort();
        v.dedup();
        v
    } else {
        args.victims.clone()
    };
    let losers: Vec<String> = {
        let mut v: Vec<String> = first.iter().map(|e| e.from.clone()).collect();
        v.sort();
        v.dedup();
        v
    };
    let mut edges: Vec<Edge> = first.into_iter().filter(|e| victims.contains(&e.from)).collect();
    if edges.is_empty() {
        return Err(anyhow!(
            "no value left {} in {}; wallets that did lose value there: {}",
            victims.join(", "),
            args.signature,
            if losers.is_empty() { "none".to_string() } else { losers.join(", ") }
        ));
    }
    let mut nodes: Vec<Node> = Vec::new();
    let mut queue: VecDeque<(String, usize, String, u64)> = VecDeque::new();
    let kind = |a: &str, seed: bool| if off_curve(a) { "program-owned" } else if seed { "seed" } else { "wallet" };
    for e in &edges {
        if !nodes.iter().any(|n| n.address == e.to) {
            let k = kind(&e.to, true);
            nodes.push(Node { address: e.to.clone(), hop: 1, first_seen_slot: e.slot, kind: k, label: args.labels.get(&e.to).cloned(), transactions_read: 0, truncated: false });
            if k != "program-owned" && !args.labels.contains_key(&e.to) {
                queue.push_back((e.to.clone(), 1, e.signature.clone(), e.slot));
            }
        }
    }

    while let Some((wallet, hop, since, _slot)) = queue.pop_front() {
        if hop > args.hops {
            continue;
        }
        let pubkey = Pubkey::from_str(&wallet)?;
        // Newer than the transaction that tainted this wallet, oldest first.
        let mut sigs = rpc.signatures(&pubkey, args.max_tx_per_wallet + 1, Some(&since), None)?;
        let truncated = sigs.len() > args.max_tx_per_wallet;
        sigs.truncate(args.max_tx_per_wallet);
        sigs.reverse();
        let mut read = 0;
        for s in sigs.iter().filter(|s| !s.failed) {
            let Some(tx) = rpc.balances(&s.signature)? else { continue };
            read += 1;
            for e in flows(&tx, args.min_lamports, hop).into_iter().filter(|e| e.from == wallet) {
                if !nodes.iter().any(|n| n.address == e.to) && nodes.len() < args.max_nodes {
                    let k = kind(&e.to, false);
                    nodes.push(Node { address: e.to.clone(), hop: hop + 1, first_seen_slot: e.slot, kind: k, label: args.labels.get(&e.to).cloned(), transactions_read: 0, truncated: false });
                    if k != "program-owned" && !args.labels.contains_key(&e.to) {
                        queue.push_back((e.to.clone(), hop + 1, e.signature.clone(), e.slot));
                    }
                }
                edges.push(e);
            }
        }
        if let Some(n) = nodes.iter_mut().find(|n| n.address == wallet) {
            n.transactions_read = read;
            n.truncated = truncated;
        }
    }

    // Where traced tokens sit now, and who can freeze them.
    let mut mints: Vec<String> = edges.iter().filter(|e| e.asset != "SOL").map(|e| e.asset.clone()).collect();
    mints.sort();
    mints.dedup();
    let mint_keys: Vec<Pubkey> = mints.iter().filter_map(|m| Pubkey::from_str(m).ok()).collect();
    let (_, mint_accounts) = rpc.accounts(&mint_keys)?;
    let freeze: HashMap<String, Option<String>> = mints
        .iter()
        .zip(mint_accounts)
        .map(|(m, a)| {
            let fa = a.and_then(|a| (a.data.len() >= 82 && a.data[46..50] == [1, 0, 0, 0]).then(|| Pubkey::new_from_array(a.data[50..82].try_into().unwrap()).to_string()));
            (m.clone(), fa)
        })
        .collect();
    let mut holdings = Vec::new();
    for n in nodes.iter().filter(|n| n.kind != "program-owned") {
        for m in &mints {
            if !edges.iter().any(|e| e.to == n.address && &e.asset == m) {
                continue;
            }
            for (account, amount) in rpc.token_holdings(&n.address, m)? {
                if amount > 0 {
                    holdings.push(Holding { wallet: n.address.clone(), token_account: account, mint: m.clone(), amount, freeze_authority: freeze.get(m).cloned().flatten() });
                }
            }
        }
    }
    Ok(Trace {
        start: args.signature.clone(),
        victims,
        nodes,
        edges,
        holdings,
        limits: format!("{} hops, {} transactions per wallet, {} addresses, SOL moves under {} lamports ignored", args.hops, args.max_tx_per_wallet, args.max_nodes, args.min_lamports),
    })
}

fn short(a: &str) -> String {
    if a.len() > 10 { format!("{}…{}", &a[..4], &a[a.len() - 4..]) } else { a.to_string() }
}

fn amount(raw: u128, decimals: u8) -> String {
    let d = 10u128.pow(decimals as u32);
    let frac = format!("{:0width$}", raw % d, width = decimals as usize);
    let frac = frac.trim_end_matches('0');
    if frac.is_empty() { format!("{}", raw / d) } else { format!("{}.{}", raw / d, frac) }
}

/// Markdown incident report: summary, timeline, graph, holdings, freeze contacts.
pub fn report(t: &Trace) -> String {
    let mut s = String::new();
    let name = |a: &str| t.nodes.iter().find(|n| n.address == a).and_then(|n| n.label.clone()).map(|l| format!("{l} ({})", short(a))).unwrap_or_else(|| short(a));
    let _ = writeln!(s, "# Incident trace\n\nStart transaction: `{}`  \nVictim wallets: {}  \nLimits: {}\n", t.start, t.victims.iter().map(|v| format!("`{v}`")).collect::<Vec<_>>().join(", "), t.limits);
    let followed = t.nodes.iter().filter(|n| n.kind != "program-owned").count();
    let _ = writeln!(s, "{} addresses reached, {} followed, {} flows recorded. Edges marked *inferred* split value pro rata inside a transaction with several senders and receivers.\n", t.nodes.len(), followed, t.edges.len());
    let _ = writeln!(s, "## Timeline\n\n| Hop | Slot | From | To | Amount | Asset | Transaction |\n|---|---|---|---|---|---|---|");
    let mut edges = t.edges.clone();
    edges.sort_by_key(|e| (e.slot, e.hop));
    for e in &edges {
        let _ = writeln!(s, "| {} | {} | {} | {} | {}{} | {} | `{}` |", e.hop, e.slot, name(&e.from), name(&e.to), amount(e.amount, e.decimals), if e.inferred { " *inferred*" } else { "" }, short(&e.asset), short(&e.signature));
    }
    let _ = writeln!(s, "\n## Flow graph\n\n```mermaid\nflowchart LR");
    let mut ids: HashMap<&str, usize> = HashMap::new();
    for e in &t.edges {
        for a in [&e.from, &e.to] {
            let n = ids.len();
            ids.entry(a.as_str()).or_insert(n);
        }
    }
    for (a, i) in &ids {
        let shape = if t.victims.iter().any(|v| v == a) { format!("n{i}[[\"victim {}\"]]", name(a)) } else if off_curve(a) { format!("n{i}[(\"{}\")]", name(a)) } else { format!("n{i}[\"{}\"]", name(a)) };
        let _ = writeln!(s, "  {shape}");
    }
    let mut seen = std::collections::HashSet::new();
    for e in &t.edges {
        if seen.insert((e.from.clone(), e.to.clone(), e.asset.clone())) {
            let total: u128 = t.edges.iter().filter(|x| x.from == e.from && x.to == e.to && x.asset == e.asset).map(|x| x.amount).sum();
            let _ = writeln!(s, "  n{} -- \"{} {}\" --> n{}", ids[e.from.as_str()], amount(total, e.decimals), short(&e.asset), ids[e.to.as_str()]);
        }
    }
    let _ = writeln!(s, "```\n\n## Where traced tokens are now\n");
    if t.holdings.is_empty() {
        let _ = writeln!(s, "No traced wallet still holds a traced token.");
    } else {
        let _ = writeln!(s, "| Wallet | Token account | Mint | Amount (raw) | Freeze authority |\n|---|---|---|---|---|");
        for h in &t.holdings {
            let _ = writeln!(s, "| `{}` | `{}` | `{}` | {} | {} |", h.wallet, h.token_account, h.mint, h.amount, h.freeze_authority.as_deref().map(|f| format!("`{f}`")).unwrap_or_else(|| "none".into()));
        }
        let _ = writeln!(s, "\nA mint with a freeze authority can have these token accounts frozen by its issuer. Those issuers are the first contacts.");
    }
    let _ = writeln!(s, "\n## Program-owned destinations (not followed)\n");
    for n in t.nodes.iter().filter(|n| n.kind == "program-owned") {
        let _ = writeln!(s, "- `{}` (first seen slot {}): off-curve, owned by a program: a pool, vault or bridge. Value here was swapped or deposited; follow it from that program's side.", n.address, n.first_seen_slot);
    }
    let truncated: Vec<&Node> = t.nodes.iter().filter(|n| n.truncated).collect();
    if !truncated.is_empty() {
        let _ = writeln!(s, "\n## Not fully read\n");
        for n in truncated {
            let _ = writeln!(s, "- `{}`: more than the transaction limit after it was reached; raise `--max-tx`.", n.address);
        }
    }
    s
}
