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

The share-value and solvency checks are the same functions
(`fuzzforge_scenarios::invariants::{share_value_fell, solvency}`) that the
CP-Swap harness asserts. A rule's false-alarm rate is therefore a measured
number: the campaign shows how often it fired on legitimate activity, and the
planted-fault canary shows that it fires on a real fault.

Sentinel never sends a transaction. The firewall simulates locally and the
monitor only reads.

## Commands

```sh
cargo build --release
B=target/release/sentinel
P=policies/raydium-cp-swap.toml

$B policy $P                               # review: every rule, why, evidence, policy sha256
$B check  --policy $P --tx <base64|@file>  # firewall: one pending transaction → decision
$B replay --policy $P --signature <sig>    # firewall on a real past transaction, as if pending now
$B drill  --policy $P --pool <pool> [--candidate-so other.so]   # fresh test cases, pass/fail
$B watch  --policy $P --pool <pool>... [--interval 15] [--out findings.jsonl]
$B backtest --policy $P --pool <pool> --limit 300
```

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

## How the firewall works

1. Decode the transaction (legacy, v0 or v1) and resolve address lookup tables.
2. Clone every account it names from the RPC into a local LiteSVM at one slot,
   including upgradeable programs' deployed bytes, plus the vaults of every
   CP-Swap pool it touches, whether it calls the pool directly or through a
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

- **Unit tests** (`cargo test`, 9 passing): policy loading rejects typos and
  unknown fields; each rule fires on its canary and stays quiet at its limit;
  forged events are ignored; instruction decoding.
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

## Not done yet

- Only CP-Swap has an adapter (`src/cpswap.rs`). Another protocol needs
  layouts, events and its invariants; the rule engine, fork and policy loader
  are shared.
- Drills need pools of plain mints. They skip pools whose Token-2022 mints
  have extensions, because their token accounts need extension space.
- Fund tracing and incident coordination are not built. Findings already
  carry the slot, signature, pool and policy hash, which is the input a
  tracer would start from.
