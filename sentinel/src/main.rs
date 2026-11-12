use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use fuzzforge_sentinel::{check, fork, monitor, policy::Policy, rpc::Rpc};
use fuzzforge_scenarios::anchor::ix_discriminator;
use solana_pubkey::Pubkey;

#[derive(Parser)]
#[command(name = "sentinel", about = "Monitor and pre-signing firewall that enforce fuzz-validated invariants from a reviewable policy")]
struct Cli {
    /// Read-only RPC endpoint. Nothing is ever sent to it.
    #[arg(long, env = "SENTINEL_RPC", default_value = "https://api.mainnet-beta.solana.com", global = true)]
    rpc: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, ValueEnum)]
enum Canary {
    /// Loosen the first CP-Swap swap's signed bound to "anything goes"
    /// (min_out = 0, or max_in = u64::MAX) before checking it.
    LooseBound,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print a policy's rules for review, with its SHA-256.
    Policy { file: String },
    /// Firewall: decide on one pending transaction (base64 or base58, or @file).
    Check {
        #[arg(long)]
        policy: String,
        #[arg(long)]
        tx: String,
    },
    /// Firewall on a real past transaction, re-run as if it were pending now.
    Replay {
        #[arg(long)]
        policy: String,
        #[arg(long)]
        signature: String,
        #[arg(long, value_enum)]
        canary: Option<Canary>,
    },
    /// Monitor: watch pools continuously, one JSON line per finding.
    Watch {
        #[arg(long)]
        policy: String,
        #[arg(long = "pool", required = true)]
        pools: Vec<Pubkey>,
        #[arg(long, default_value_t = 15)]
        interval: u64,
        /// Stop after this many rounds (default: run until killed).
        #[arg(long)]
        rounds: Option<u64>,
        #[arg(long, default_value_t = 25)]
        max_tx_per_round: usize,
        /// Append findings here instead of stdout.
        #[arg(long)]
        out: Option<String>,
        /// Also POST every finding as JSON to this webhook (best effort).
        #[arg(long)]
        alert_url: Option<String>,
    },
    /// Fresh transactions from a synthetic user against a live pool, each with
    /// the verdict the policy should reach. Exit 0 only if every case matches.
    Drill {
        #[arg(long)]
        policy: String,
        #[arg(long)]
        pool: Pubkey,
        /// Another build of the program, to drill the upgrade rule.
        #[arg(long)]
        candidate_so: Option<String>,
    },
    /// Incident response: follow funds out of one transaction, hop by hop.
    Trace {
        #[arg(long)]
        signature: String,
        /// Wallet that lost funds (repeatable). Default: every wallet whose balance fell.
        #[arg(long = "from")]
        victims: Vec<String>,
        #[arg(long, default_value_t = 2)]
        hops: usize,
        #[arg(long, default_value_t = 20)]
        max_tx: usize,
        #[arg(long, default_value_t = 40)]
        max_nodes: usize,
        #[arg(long, default_value_t = 10_000_000)]
        min_lamports: u128,
        /// TOML table of `address = "label"`; labelled addresses are named and not followed.
        #[arg(long)]
        labels: Option<String>,
        /// Write the Markdown incident report here (JSON goes to stdout).
        #[arg(long)]
        report: Option<String>,
    },
    /// Measure every rule of a draft policy against drills and live history;
    /// writes the policy back with `vetted` lines. Exit 1 if any rule is rejected.
    Vet {
        #[arg(long)]
        policy: String,
        #[arg(long = "pool", required = true)]
        pools: Vec<Pubkey>,
        #[arg(long, default_value_t = 10)]
        rounds: u64,
        #[arg(long, default_value_t = 15)]
        interval: u64,
        #[arg(long, default_value_t = 300)]
        backtest: usize,
        /// Another build of the program, to drill the upgrade pin (CP-Swap).
        #[arg(long)]
        candidate_so: Option<String>,
        /// Where to write the vetted policy (default: overwrite --policy).
        #[arg(long)]
        out: Option<String>,
    },
    /// Record a reviewer's sign-off on a vetted policy.
    Sign {
        #[arg(long)]
        policy: String,
        #[arg(long)]
        reviewer: String,
        #[arg(long)]
        accept_untested: bool,
    },
    /// Run the history-based rules over a pool's recent transactions.
    Backtest {
        #[arg(long)]
        policy: String,
        #[arg(long)]
        pool: Pubkey,
        #[arg(long, default_value_t = 300)]
        limit: usize,
    },
}

fn exit_code(verdict: &str) -> i32 {
    match verdict {
        "allow" => 0,
        "allow-with-alert" => 1,
        "hold" => 2,
        _ => 3,
    }
}

fn decide(rpc: &Rpc, policy: &Policy, tx: &solana_transaction::versioned::VersionedTransaction) -> Result<i32> {
    let d = check::check(rpc, policy, tx)?;
    println!("{}", serde_json::to_string_pretty(&d)?);
    Ok(exit_code(d.verdict))
}

fn loosen(tx: &mut solana_transaction::versioned::VersionedTransaction, program: &Pubkey) -> Result<()> {
    let keys = tx.message.static_account_keys().to_vec();
    let ixs = match &mut tx.message {
        solana_message::VersionedMessage::Legacy(m) => &mut m.instructions,
        solana_message::VersionedMessage::V0(m) => &mut m.instructions,
        solana_message::VersionedMessage::V1(m) => &mut m.instructions,
    };
    for ix in ixs {
        if keys.get(ix.program_id_index as usize) != Some(program) || ix.data.len() < 24 {
            continue;
        }
        if ix.data[..8] == ix_discriminator("swap_base_input") {
            ix.data[16..24].copy_from_slice(&0u64.to_le_bytes());
            eprintln!("[canary] swap_base_input minimum_amount_out set to 0");
            return Ok(());
        }
        if ix.data[..8] == ix_discriminator("swap_base_output") {
            ix.data[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
            eprintln!("[canary] swap_base_output max_amount_in set to u64::MAX");
            return Ok(());
        }
    }
    bail!("no top-level CP-Swap swap in this transaction to loosen")
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let rpc = Rpc::new(&cli.rpc);
    let code = match cli.cmd {
        Cmd::Policy { file } => {
            let p = Policy::load(&file)?;
            println!("{} v{}  {}  program {}\nsha256 {}", p.name, p.version, p.protocol.name(), p.program, p.sha256);
            if let Some(d) = &p.drafted_by {
                println!("drafted by {d}");
            }
            match &p.signoff {
                Some(so) if p.signoff_valid => println!("signed off by {} on {}", so.reviewer, so.date),
                Some(so) => println!("STALE SIGN-OFF by {} on {}: the file changed after it was signed", so.reviewer, so.date),
                None => println!("not signed off"),
            }
            println!();
            for r in p.describe() {
                println!("{:<18} {:<6} {}\n    why: {}", r.id, format!("{:?}", r.action).to_lowercase(), r.param, r.why);
                println!("    evidence: {}", r.evidence.unwrap_or("NONE: not yet validated"));
                if let Some(v) = r.vetted {
                    println!("    vetted: {v}");
                }
            }
            0
        }
        Cmd::Check { policy, tx } => {
            let p = Policy::load(&policy)?;
            let wire = match tx.strip_prefix('@') {
                Some(path) => std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?,
                None => tx,
            };
            decide(&rpc, &p, &fork::decode_tx(&wire)?)?
        }
        Cmd::Replay { policy, signature, canary } => {
            let p = Policy::load(&policy)?;
            let found = rpc.transaction(&signature)?.with_context(|| format!("{signature} not found"))?;
            let mut tx = fork::decode_tx(&found.wire)?;
            if let Some(Canary::LooseBound) = canary {
                loosen(&mut tx, &p.program_id())?;
            }
            decide(&rpc, &p, &tx)?
        }
        Cmd::Watch { policy, pools, interval, rounds, max_tx_per_round, out, alert_url } => {
            let p = Policy::load(&policy)?;
            let mut sink: Box<dyn std::io::Write> = match out {
                Some(path) => Box::new(std::fs::OpenOptions::new().create(true).append(true).open(path)?),
                None => Box::new(std::io::stdout()),
            };
            monitor::watch(&rpc, &p, monitor::WatchArgs { pools: &pools, interval_secs: interval, rounds, max_tx_per_round, alert_url: alert_url.as_deref() }, &mut *sink)?;
            0
        }
        Cmd::Drill { policy, pool, candidate_so } => {
            let p = Policy::load(&policy)?;
            let cases = fuzzforge_sentinel::drill::drill(&rpc, &p, &pool, candidate_so.as_deref())?;
            let mut failed = 0;
            for c in &cases {
                let ok = c.decision.verdict == c.expect;
                failed += (!ok) as i32;
                println!("{} {:<48} expected {:<17} got {:<17} cu {}", if ok { "PASS" } else { "FAIL" }, c.name, c.expect, c.decision.verdict, c.decision.compute_units);
                for f in &c.decision.findings {
                    println!("       {} [{:?}] {}", f.rule, f.action, f.detail);
                }
            }
            let deployed = cases.iter().find_map(|c| c.decision.program_sha256.clone()).unwrap_or_default();
            println!("{} of {} cases matched; policy sha256 {}; program sha256 in fork {}", cases.len() as i32 - failed, cases.len(), p.sha256, deployed);
            (failed > 0) as i32
        }
        Cmd::Trace { signature, victims, hops, max_tx, max_nodes, min_lamports, labels, report } => {
            let labels: std::collections::HashMap<String, String> = match labels {
                Some(path) => toml::from_str(&std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?)?,
                None => Default::default(),
            };
            let args = fuzzforge_sentinel::trace::TraceArgs { signature, victims, hops, max_tx_per_wallet: max_tx, max_nodes, min_lamports, labels };
            let t = fuzzforge_sentinel::trace::trace(&rpc, &args)?;
            if let Some(path) = report {
                std::fs::write(&path, fuzzforge_sentinel::trace::report(&t))?;
                eprintln!("[trace] report written to {path}");
            }
            println!("{}", serde_json::to_string_pretty(&t)?);
            0
        }
        Cmd::Vet { policy, pools, rounds, interval, backtest, candidate_so, out } => {
            let args = fuzzforge_sentinel::vet::VetArgs { pools: &pools, rounds, interval_secs: interval, backtest_limit: backtest, candidate_so: candidate_so.as_deref() };
            let (verdicts, text) = fuzzforge_sentinel::vet::vet(&rpc, &policy, &args)?;
            let target = out.unwrap_or(policy);
            std::fs::write(&target, &text)?;
            let mut rejected = 0;
            for v in &verdicts {
                rejected += (v.verdict == "REJECT") as i32;
                println!("{:<8} {:<18} {}", v.verdict, v.rule, v.detail);
            }
            println!("wrote {target}");
            (rejected > 0) as i32
        }
        Cmd::Sign { policy, reviewer, accept_untested } => {
            let signed = fuzzforge_sentinel::vet::sign(&policy, &reviewer, accept_untested)?;
            std::fs::write(&policy, signed)?;
            println!("signed {policy} as {reviewer}");
            0
        }
        Cmd::Backtest { policy, pool, limit } => {
            let p = Policy::load(&policy)?;
            let bt = monitor::backtest(&rpc, &p, &pool, limit)?;
            println!("{}", serde_json::to_string_pretty(&bt)?);
            0
        }
    };
    std::process::exit(code)
}
