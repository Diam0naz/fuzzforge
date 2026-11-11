# Case study: Raydium CP-Swap, before and after launch

| | |
| --- | --- |
| Program | Raydium CP-Swap, `CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C` |
| Source | [raydium-io/raydium-cp-swap](https://github.com/raydium-io/raydium-cp-swap) at `3d69122`, built locally (`cargo build-sbf --tools-version v1.58`), sha256 `1cf5ce07…e89609` |
| Deployed build | dumped from mainnet 2026-11-11, sha256 `c383e1c5…66818d` |
| Engine | Crucible `26c2391` (LiteSVM 0.15.2), Fuzzforge scenario library, Sentinel |
| Dates | 2026-11-10 and 2026-11-11 |

**Scope statement.** This is a fuzzing case study, not an audit. A property
that did not fail was not proven to hold. All testing ran locally or read
public mainnet state; nothing was sent to mainnet. No vulnerability was found.
If one had been, it would have gone to Raydium's bug bounty and not here.

## Summary

CP-Swap is a constant-product AMM that accepts SPL Token and a documented
subset of Token-2022 extensions. The question was whether its mint handling
and token-transfer accounting hold up against every token type it says it
supports, including transfer fees at their extremes.

- **Before launch:** about 0.9M stateless executions and 2.3M stateful
  iterations across nine pools of hostile mint pairs found **no violation**
  of solvency, LP share value, slippage, deposit fairness or compute limits.
  A planted fault for each check was caught within seconds, which shows the
  checks can fire.
- **Upgrade-diff:** the local build and the build deployed on mainnet agreed
  on every one of 1,687,394 fuzzed instructions.
- **After launch:** the same invariants run as a monitor and a pre-signing
  firewall on live mainnet pools (Sentinel). Every rule in the policy was
  measured against live drills and history before being trusted.

## 1. Mint policy preflight

CP-Swap documents which Token-2022 extensions it supports. Before fuzzing,
the harness creates a pool with each profile and checks that the program
accepts or rejects it as documented.

| Mint profile | Documented | Observed |
| --- | --- | --- |
| Token-2022, transfer fee 1% | supported | accepted |
| Token-2022, transfer fee 2.5% capped at 7 units | supported | accepted |
| Token-2022, transfer fee 100% capped at 5,000 units | supported | accepted |
| Token-2022, interest-bearing | supported | accepted |
| Token-2022, transfer hook | unsupported | rejected |
| Token-2022, permanent delegate | unsupported | rejected |
| Token-2022, non-transferable | unsupported | rejected |

All seven matched the documentation.

## 2. What was fuzzed

There were nine pools. Each pairs two mints from the supported set: classic
SPL Token, plain Token-2022, three transfer-fee variants and interest-bearing.
Three pools are created with `initialize_v2` with creator fees on (both
tokens, token 0 only, token 1 only). Two users act on them.

Actions: deposit, withdraw, swap (exact input and exact output), donation
straight into a vault, creator-fee collection, the mint issuer changing its
transfer fee, clock advance and epoch advance (so scheduled fee changes take
effect while pools hold balances).

Properties checked after every action:

| Property | Statement |
| --- | --- |
| Solvency | Each vault holds at least the protocol, fund and creator fees booked against it. |
| LP share value | `sqrt(r0·r1) / lp_supply` over LP-owned reserves (vault minus booked fees) never falls. Compared exactly in 256-bit arithmetic. |
| Slippage, on what arrives | Measured on the user's own token accounts: no swap, deposit or withdrawal takes more than the signed maximum or delivers less than the signed minimum. Each bound comes from a dry run, so it is either exact (must pass) or one unit too tight (must fail). |
| Deposit fairness | A depositor's new LP redeems for what the vault took from them, within 2 units of rounding, including after third parties donate straight into the vaults. |
| Compute | No instruction exceeds 200,000 units or dies on the meter. |

None of these needed a model of CP-Swap's curve maths. Solvency, share
value and fairness are templates from the scenario library. Slippage and
compute are measured from the outside.

## 3. Campaigns

| Campaign | Size | Result |
| --- | --- | --- |
| Stateless, first harness (6 cores) | 506,955 executions | no violation |
| Stateless, with creator-fee pools, issuer fee changes and epoch advance | 285,798 executions | no violation |
| Stateful, same harness | ~1.53M iterations | no violation |
| Stateless, with the four invariant-free checks (15 min) | ≤127,795 executions¹ | no violation |
| Stateful, same (2 cores, 15 min) | 766,329 iterations, 13,721 novel states | no violation |
| Upgrade-diff, local build vs mainnet build (4 cores, 15 min) | 132,397 executions, 1,687,394 instructions | 0 differences |

¹ An upper bound: two workers from a concurrent campaign reported into this
total, because Crucible's broker uses a fixed port. Campaigns now run one at
a time.

### Each check was shown to fire

A check that never fires might be broken. Each one has a planted fault (a
canary):

| Canary | What it plants | Caught |
| --- | --- | --- |
| `FF_CANARY=1` | skims one unit from a vault | share-value violation after 4 executions |
| `FF_CANARY=slippage` | takes one unit more than the user's signed maximum | slippage violation after 58 executions |
| `FF_CANARY=diff` | changes the reference build's state only | upgrade-diff reports the account difference |

### Compute profile

Worst case per instruction on the deployed build, over the whole mint
matrix:

| Instruction | Units (deployed) | Units (local build) | Share of 200k |
| --- | --- | --- | --- |
| `initialize` | 106,465 | 104,096 | 53% |
| `initialize_v2` | 96,922 | 94,414 | 48% |
| `collect_creator_fee` | 36,536 | 35,327 | 18% |
| `deposit` | 33,510 | 32,117 | 17% |
| `swap_base_output` | 33,149 | 31,571 | 17% |
| `withdraw` | 32,754 | 31,491 | 16% |
| `swap_base_input` | 31,977 | 30,562 | 16% |

The worst lane is a pool of a capped transfer-fee mint and a plain
transfer-fee mint. The local build is 1,209 to 2,508 units cheaper than the
deployed one on every instruction. That is consistent with a different
compiler toolchain, which upgrade-diff confirms is not a behaviour change.

## 4. After launch: the same rules on mainnet

Sentinel turns the fuzzed invariants into a monitor and a simulate-before-sign
firewall. The solvency and share-value rules call the same functions the
harness asserts. See [`sentinel/README.md`](../sentinel/README.md).

**Drill** on live pool `54GtpHJaEGKsfq6pWSRJa656zRgVFhkC5fzQBmp7qXmS`, run
against one state snapshot: 6 of 6 fresh transactions reached the expected
verdict.

| Case | Verdict | Rule that fired |
| --- | --- | --- |
| honest swap, 0.5% slippage | allow | none |
| same swap, `minimum_amount_out = 0` | hold | slippage-headroom |
| bound one unit above what the pool pays | block | must-simulate (the program's own ExceededSlippage) |
| swap of half the input reserve | allow with alert | reserve-outflow, 3,323 bps |
| honest swap plus an unlisted program | hold | program-allowlist |
| honest swap on the local build instead of the deployed one | hold | program-upgrade |

**Monitor:** 20 rounds on three live pools found no solvency or share-value
violations. **Backtest:** 300 transactions on one pool, with 160
share-value comparisons, had no false alarms.

**Vetting the policy.** Every rule is measured against drills and history
before it is trusted (`sentinel vet`), on pools `54Gt…qXmS` and `3N1C…PJvj`:

| Rule | Verdict | Measured |
| --- | --- | --- |
| solvency, share-value | QUIET | No false alarm in drills, two 200-transaction backtests or 6 watch rounds on two pools. Nothing live makes them fire; their positive evidence is the fuzz canary (section 3). |
| must-simulate, slippage-headroom, program-allowlist, program-upgrade | OK | Quiet on the honest case; each fired on the drill case built for it. |
| reserve-outflow (alert above 1,000 bps) | OK, then NOISY | Two vet runs on the same pool an hour apart. The first saw one legitimate swap take **1,024 bps** of a reserve in one instruction, just over the threshold. The second's window peaked at 646 bps. A threshold set from one short window would have been wrong. |
| compute-budget | QUIET | The honest swap used about 25k units against a 400k limit. |
| failed-burst | NOISY | 59 of 200 and 126 of 200 transactions failed on the two pools (bot traffic); 23 and 52 windows crossed the limit. It needs tuning per pool before it means anything. |

The same pipeline vetted a second protocol: a stake-pool policy drafted by
an agent for JitoSOL and bSOL (`sentinel/policies/spl-stake-pool.toml`).
Its solvency rule (no unbacked pool tokens) was OK, firing on a planted
unbacked token. Its must-simulate and allowlist rules were also OK. The
other rules were QUIET.

## 5. Limits

- **Coverage:** about 14% of the program's branch edges. The admin
  instructions (config, pool status, protocol and fund fee collection,
  permissions) were not exercised. Everything above is about the
  user-facing paths and the mint matrix.
- **Deposit fairness:** checked during the campaigns, but has no dedicated
  canary; its own logic has a unit test only.
- **Compute limit:** never triggered (the worst case is 53% of the limit), so
  the limit check has not been seen to fire in a campaign.
- **Upgrade-diff on a real change:** the only real diff run compared two
  builds of the same source. A run across a real behaviour change needs an
  older CP-Swap commit built locally.
- **The firewall's fork:** it uses LiteSVM's bundled SPL programs rather than
  mainnet's, and does not model a v1 message's requested heap size. Each
  decision lists these gaps in `fidelity_notes`.

## Reproduce

```sh
# before launch
crucible run -C targets/raydium_cp_swap raydium_cp_swap amm_invariants --release --timeout 900
FF_DIFF_SO=program/reference/<mainnet dump>.so crucible run -C targets/raydium_cp_swap raydium_cp_swap amm_invariants --release --timeout 900

# after launch
cd sentinel && cargo build --release
target/release/sentinel drill --policy policies/raydium-cp-swap.toml --pool 54GtpHJaEGKsfq6pWSRJa656zRgVFhkC5fzQBmp7qXmS \
  --candidate-so ../targets/raydium_cp_swap/program/raydium_cp_swap.so
target/release/sentinel vet --policy policies/raydium-cp-swap.toml --pool 54GtpHJaEGKsfq6pWSRJa656zRgVFhkC5fzQBmp7qXmS --out /tmp/vetted.toml
```
