# Sentinel

The runtime half of Fuzzforge. The invariants a fuzz campaign validated
before launch become the rules a **monitor** and a **pre-signing firewall**
enforce after it, from one policy file a person can review.

```
 before launch                          after launch
 ─────────────                          ────────────
 scenarios/ invariants  ──same code──►  sentinel rules
 fuzz campaign evidence ──────────────► policy `evidence` lines
 upgrade-diff campaign  ──────────────► program-upgrade pin
```

The value-per-share and solvency checks are the same functions in
`fuzzforge_scenarios::invariants` that the fuzz harnesses assert. A rule's false-alarm rate is therefore a measured
number: the campaign shows how often it fired on legitimate activity, and the
planted-fault canary shows that it fires on a real fault.

Sentinel never sends a transaction. The firewall simulates locally, and the
monitor and tracer only read.

Two protocol adapters share one engine (`src/protocol.rs`):

| Protocol | Shape | Value per share | Solvency |
|---|---|---|---|
| `raydium-cp-swap` | two reserves, LP shares | `sqrt(r0·r1)/lp` never falls | vaults ≥ booked fees |
| `spl-stake-pool` (JitoSOL, bSOL, most LSTs) | one asset, pool-token shares | lamports per pool token never falls | mint supply ≤ the pool's recorded supply (no unbacked tokens) |

## Commands

```sh
cargo build --release
B=target/release/sentinel
P=policies/raydium-cp-swap.toml

$B policy $P                               # review: every rule, why, evidence, policy sha256
$B check  --policy $P --tx <base64|@file>  # firewall: one pending transaction → decision
$B replay --policy $P --signature <sig>    # firewall on a real past transaction, as if pending now
$B drill  --policy $P --pool <pool> [--candidate-so other.so]   # fresh test cases, pass/fail
$B watch  --policy $P --pool <pool>... [--interval 15] [--out findings.jsonl] [--alert-url <webhook>]
$B backtest --policy $P --pool <pool> --limit 300
$B trace  --signature <sig> [--from <victim>] [--hops 2] --report incident.md   # follow the funds
$B vet    --policy draft.toml --pool <pool>... [--candidate-so other.so]          # measure every rule
$B sign   --policy vetted.toml --reviewer "Name"                                  # human sign-off
```

`./demo.sh` runs policy review, both drills, a short watch and a trace
against mainnet in about five minutes.

`--rpc` (or `SENTINEL_RPC`) selects the endpoint; it defaults to public mainnet.
`check` and `replay` exit 0 to allow, 1 to allow with an alert, 2 to hold and
3 to block, so a wallet, signer or CI step can gate on the exit code.

## The policy

[`policies/raydium-cp-swap.toml`](policies/raydium-cp-swap.toml). Each rule
has an `action` (`alert`, `hold` for a person, or `block`), a `why`, and an
optional `evidence` line. `sentinel policy` prints `NONE: not yet validated`
for any rule that has no evidence line.

The set of rules is closed. An unknown rule id, a misspelt one or an unknown
field makes the file fail to load, so a policy cannot list a protection that
nothing enforces. Every decision and monitor finding records the SHA-256 of
the policy file that produced it.

| Rule | Firewall | Monitor | Fires when |
|---|---|---|---|
| `solvency` | ✓ | ✓ | a vault holds less than the fees booked against it |
| `share-value` | ✓ | ✓ | `sqrt(r0·r1)/lp` over LP-owned reserves falls |
| `reserve-outflow` | ✓ | ✓ (per event) | one step removes more than `max_bps` of a reserve |
| `slippage-headroom` | ✓ | | the signed bound is looser than `max_bps` beyond the simulated outcome (a bound the program breaks always blocks) |
| `program-allowlist` | ✓ | | any program outside the list runs, at any CPI depth |
| `program-upgrade` | ✓ | ✓ | the deployed program's SHA-256 is not the pinned build |
| `compute-budget` | ✓ | | the transaction uses more than `max_units` |
| `must-simulate` | ✓ | | the transaction fails against current state |
| `failed-burst` | | ✓ | more than `max_failed` of the last `window` transactions on a pool failed (probing) |
| `reserve-drop` | | ✓ | a reserve leg fell more than `max_bps` between monitor rounds (a drain or run spread across many transactions) |
| `foreign-cpi` | | ✓ | a program outside the allowlist touched the pool in a recent transaction (abnormal CPI / unexpected integrator) |

## Drafted, vetted, signed

A policy goes through three hands before it protects anything:

1. **Drafted** by a person or by an agent following [`AGENTS.md`](AGENTS.md).
   A draft can only choose rules from the closed set and set their
   parameters, so a drafter, human or model, cannot invent a check that
   nothing enforces. `drafted_by` records who drafted it.
2. **Vetted** by `sentinel vet`, which measures every rule. Drill cases
   check that each rule fires on the case built for it and stays quiet on
   the honest one. Backtests and watch rounds count any finding on real,
   landed transactions as a false alarm. Each rule gets a `vetted` line:

   | Verdict | Meaning |
   |---|---|
   | `OK` | Quiet on legitimate activity and fires on its drill case. |
   | `QUIET` | Quiet on legitimate activity, but nothing here makes it fire. |
   | `NOISY` | An alert rule that fired on legitimate activity. |
   | `REJECT` | A hold or block rule that fired on legitimate activity, or a rule that missed its own drill case. |
   | `UNTESTED` | Nothing exercised it. |

3. **Signed** by a person with `sentinel sign`, which refuses rejected or
   unvetted rules. The sign-off records the SHA-256 of the file above it, so
   any later edit, such as weakening a rule, makes it stale. Every firewall
   decision records who signed the policy it was made under, or `null`.

## How tracing works

`trace` starts from one transaction: a monitor finding, or the exploit
itself. Per asset, wallets whose balance fell are sources and wallets whose
balance rose are sinks. With several of each in one transaction, value is
split pro rata and the edge is marked *inferred*. The trace then reads each
tainted wallet's later transactions, oldest first, for `--hops` hops.

Off-curve destinations (PDAs: pool vaults, program authorities) are named
and not followed, because value there belongs to a program. A `--labels`
file names known addresses, for example exchange deposit wallets, and stops
the trace there. The Markdown report includes:

- a timeline;
- a Mermaid flow graph;
- the token accounts still holding traced tokens;
- each mint's freeze authority, i.e. which issuers can freeze those
  accounts and should be contacted first.

Taint is per wallet: once a wallet is reached, everything it sends later is
followed, including value it held before. This over-approximates on purpose,
and an analyst prunes it.

## How the firewall works

1. Decode the transaction (legacy, v0 or v1) and resolve address lookup tables.
2. Clone every account it names from the RPC into a local LiteSVM at one slot,
   including upgradeable programs' deployed bytes, plus the accounts a
   snapshot of every market it touches needs (CP-Swap vaults, a stake pool's
   mint), whether it calls the pool directly or through a
   router. It also copies the cluster clock.
3. Run it, then compare pool state and the user's token balances before and
   after.

Each decision records `fidelity_notes`, the known gaps between the local run
and the cluster. Today the only gap is that a v1 message's requested heap size
is not modelled. A v1 message's compute limit is applied from the message.

## How the monitor works

Each round, `watch` reads each pool's state account and both vaults in one
`getMultipleAccounts` call, so all three come from the same slot. It then
checks solvency and share value against the previous round, reads the pool's
new transactions and checks every CP-Swap event in them for reserve outflow,
tracks the failure rate, and checks the program's deploy slot. It re-hashes
the program only when that slot moves. Findings are JSON lines, one per
finding.

Events count only while CP-Swap itself is the innermost frame of the log's
invoke stack. Another program in the same transaction can log a byte-identical
event, but the monitor will not take it as CP-Swap's.

## Verified on mainnet (2026-11-11)

- **Unit tests** (`cargo test`, 13 passing). They cover:
  - policy loading rejects typos and unknown fields;
  - each rule fires on its canary and stays quiet at its limit;
  - forged events are ignored;
  - instruction and stake-pool layout decoding;
  - trace flow attribution (fees, swaps, pro rata, rent noise);
  - sign-off gating and staleness.
- **Drill** on live pool `54GtpHJaEGKsfq6pWSRJa656zRgVFhkC5fzQBmp7qXmS`
  against one state snapshot: 6 of 6 cases reached the expected verdict.

  | Case | Verdict | Fired |
  |---|---|---|
  | honest swap, 0.5% slippage | allow | none |
  | the same swap with `minimum_amount_out = 0` | hold | slippage-headroom |
  | bound one unit above what the pool pays | block | must-simulate (the program's own ExceededSlippage) |
  | swap of half the input reserve | allow-with-alert | reserve-outflow (3,323 bps) |
  | honest swap plus a Memo v1 instruction | hold | program-allowlist |
  | honest swap on the local build instead of mainnet | hold | program-upgrade (`1cf5ce07…` vs pin `c383e1c5…`) |

- **Replay** of 27 recent successful CP-Swap transactions (26 completed; one
  RPC disconnect). Every fork reported the deployed program hash
  `c383e1c5…`, so the pin matched the program on mainnet. Twenty-three were
  blocked, because they fail when re-run minutes later: almost all are
  arbitrage and MEV bots or Jupiter routes with tight bounds. The other three
  simulated cleanly and were held for programs outside the allowlist. This is
  why false-alarm testing uses drills and backtests rather than replays.

- **Monitor**: 20 rounds on three live pools (slots 468,127,041 to
  468,129,354, about 15 minutes), 63 transactions read. No solvency or
  share-value findings. One `failed-burst` alert, on `3N1C…PJvj` (17 of its
  last 20 transactions failed), reported once rather than every round.
- **Backtest** of `54Gt…qXmS`, 300 signatures over slots 468,115,961 to
  468,129,253: 161 swap events and 160 share-value comparisons, with zero
  share-value or reserve-outflow firings. `failed-burst` is noisy on this
  pool: 116 of the 300 transactions failed (bot traffic), and 38 windows
  crossed the 15-of-20 limit. The policy's evidence line says so; the limit
  should be tuned per pool.

- **Stake pool drill** on JitoSOL (`Jito4APyf642JPZPx3hGc6WWJ8zPKtRbRs4P815Awbb`):
  4 of 4. A 1 SOL deposit at the exact quote (762,809,120 pool tokens) is
  allowed. A bound one token tighter is blocked by the program itself. An
  unlisted program is held. One unbacked pool token planted in the fork's
  mint is blocked by `solvency`.
- **Stake pool monitor**: 15 rounds on JitoSOL and bSOL, no findings, and the
  pinned program hash matched. No epoch boundary fell in the window, so the
  epoch-update path (where rewards are booked) has not been observed.
- **Trace** from three real CP-Swap swaps, with the vault authority as the
  "victim". This is a demonstration of the mechanics, not an incident: one
  run reached 7 addresses over 1 followed hop. It recorded the swapper's
  onward transfers, named six program-owned destinations without following
  them, and found the traced token still in the swapper's account, whose
  mint has no freeze authority.

- **Vet**, CP-Swap policy, on `54Gt…qXmS` and `3N1C…PJvj` with
  `--candidate-so`, 200-transaction backtests and 6 watch rounds:
  - **OK:** must-simulate, slippage-headroom, program-allowlist,
    program-upgrade and reserve-outflow.
  - **QUIET:** solvency, share-value and compute-budget.
  - **NOISY:** failed-burst.

  An earlier vet an hour before found one legitimate swap taking 1,024 bps
  of a reserve. That made reserve-outflow NOISY against its 1,000 bps alert
  threshold; the later window peaked at 646 bps.
- **Vet**, agent-drafted stake-pool policy, on JitoSOL and bSOL:
  - **OK:** solvency, must-simulate and program-allowlist.
  - **QUIET:** share-value, reserve-outflow, program-upgrade and
    failed-burst.

  Neither policy is signed: signing is a person's step.

## Not done yet

- **Adapters:** CP-Swap and SPL Stake Pool only. Another protocol needs its
  layouts and its value-per-share and solvency predicates; the rule engine,
  fork, monitor, tracer and policy loader are shared.
- **Stake pool evidence:** no fuzz campaign yet, so its solvency and
  share-value rules are vetted on live state and drills only. It has no
  backtest, because the program logs no events.
- **Drills need plain mints:** they skip CP-Swap pools whose Token-2022
  mints have extensions, because their token accounts need extension space.
- **Trace:** taint is per wallet, inferred edges are pro rata, and there is
  no shipped label set for exchanges or bridges (bring your own `--labels`).
