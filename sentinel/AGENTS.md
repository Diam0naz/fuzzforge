# Drafting a Sentinel policy (for coding agents)

You are drafting the rules a monitor and pre-signing firewall will enforce
for one Solana program. Your draft is a starting point. A machine vets it
against live evidence, and a person signs it before it protects anything.
You may not vet or sign.

## What you may do

1. Pick the adapter in `src/protocol.rs` that matches the program's shape
   and set `protocol`:
   - `raydium-cp-swap`: two reserves and LP shares.
   - `spl-stake-pool`: one asset and pool-token shares.

   If neither fits, stop and say so. A new adapter is code that a person
   reviews, not policy.
2. Choose rules **only** from the closed set below and set their parameters.
   Any other rule id or field makes the file fail to load, by design.
3. Give every rule a `why` in one or two sentences, written for the
   reviewer: what the rule protects and why this action and threshold.
4. Set `drafted_by` to who you are, including the model, e.g.
   `"agent: <tool> (<model id>), from <what you read>"`.

## What you must not do

- Do not write `evidence` or `vetted` lines. Evidence comes from fuzz
  campaigns and the vet run, never from the drafter.
- Do not write a `[signoff]` table.
- Do not loosen a rule so that it passes vetting. If a rule is rejected,
  report the rejection, then change the threshold or the action and explain
  why in its `why`.
- Do not add programs to `program-allowlist` that you have not seen the
  protected program's own instructions invoke (by CPI or as required
  companions such as compute budget and token programs).

## The rule set

| Rule | Parameters | Typical action |
|---|---|---|
| `solvency` | none | block |
| `share-value` | none | block |
| `reserve-outflow` | `max_bps` | alert |
| `slippage-headroom` | `max_bps` (CP-Swap only) | hold |
| `program-allowlist` | `programs = ["<id>  label", …]` | hold |
| `program-upgrade` | `sha256` of the deployed bytes | hold |
| `compute-budget` | `max_units` | alert |
| `must-simulate` | none | block |
| `failed-burst` | `window`, `max_failed` | alert |

For `program-upgrade`, take the hash from `sentinel drill` output
("program sha256 in fork") on the deployed program. Do not copy it from
anywhere else.

## Then

```sh
sentinel policy <draft>.toml                      # must load
sentinel vet --policy <draft>.toml --pool <market> [--pool <market>…] --out <draft>.vetted.toml
```

Report every verdict to the person:

| Verdict | Meaning |
|---|---|
| `OK` | Quiet on legitimate activity, and fires on its drill case. |
| `QUIET` | Quiet on legitimate activity, but nothing in the vet run makes it fire. Its positive evidence must come from elsewhere: a fuzz campaign's canary, or a drill with `--candidate-so`. |
| `NOISY` | An alert rule that fired on legitimate activity. |
| `REJECT` | A hold or block rule that fired on legitimate activity, or a rule that did not fire on its own drill case. |
| `UNTESTED` | Nothing in the vet run exercised it. |

A person reads the vetted file and, if they accept it, runs
`sentinel sign --policy <file> --reviewer "<name>"`. Signing refuses any
rejected or unvetted rule. Any later edit makes the sign-off stale, and
every decision records who signed the policy it was made under.
