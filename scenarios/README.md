# fuzzforge-scenarios

Reusable hostile scenarios for [Crucible](https://github.com/asymmetric-research/crucible)
harnesses. Use this crate for the cases Crucible's `--mutate-accounts` engine
skips. Don't re-implement the account checks it already covers: owner, signer,
PDA, type tag, duplicate accounts, and accounts forwarded into a CPI.

| Module | Provides |
| --- | --- |
| `token2022` | `MintProfile` matrix (SPL Token, plain Token-2022, transfer fee at three settings, permanent delegate, transfer hook, freeze authority, non-transferable, interest-bearing) created through the real token programs; `TokenEnv` with attacker helpers (`attacker_pull`, `attacker_freeze`, `issuer_set_transfer_fee`, `donate`); `read_token_account`, which handles extensions |
| `invariants` | `CustodyLedger` (a balance moves only through authorized flows, and tracks fee shortfall), `LivenessLog` (an exit or deposit that must succeed did succeed), `ShareValueLedger` (the value of one LP share never falls), `deposit_fairness` (new shares redeem for what the vault took), `summarize_logs` |
| `diff` | Upgrade-diff fuzzing: `first_difference` compares named accounts across two builds' contexts, `outcome_difference` compares an instruction's success or failure |
| `compute` | Compute-unit high-water marks per build, instruction and lane; a limit check (`FF_CU_LIMIT`); detection of transactions that ran out of budget |
| `anchor` | IDL-free Anchor instruction builder and discriminators, deterministic keypairs |

## Checks that need no protocol-specific invariant

Writing invariants is the slow, per-client part of a campaign. These four
checks apply to almost any program that holds tokens, and a harness gets them
by routing its actions through a few helpers:

1. **Upgrade-diff.** Build the world twice, once per build of the program, and
   apply every fuzzed step to both. Any difference in an instruction's outcome
   or in the resulting accounts is a behaviour change, found without stating
   what correct behaviour is. The previous build is the oracle.
2. **Slippage on what arrives.** Dry-run an instruction on a copy of the state
   to learn what it moves, then send it with limits that are exact (must
   succeed) or one unit too tight (must fail), and measure the user's own
   token accounts. This catches limits checked before a transfer fee is taken.
3. **Donation.** Transfer tokens straight into the program's vaults
   (`TokenEnv::donate`) and keep checking `deposit_fairness` and
   `ShareValueLedger` in the states that creates.
4. **Compute cliff.** Feed every successful instruction's compute units to
   `compute::observe`. It flags anything over the limit and writes the
   high-water table to `FF_CU_OUT`; merge it with `tools/cu-profile.sh`.

`../targets/raydium_cp_swap` uses all four. Each has a self-test there
(`FF_CANARY`), because a check that cannot fire proves nothing.

**Pitfall this crate works around:** `TestContext::token_balance` decodes token
accounts with the classic SPL layout, and returns `0` for any Token-2022 account
that has extensions. Always use `token2022::read_token_account` instead.

To use it in a harness:

```toml
fuzzforge-scenarios = { path = "../../scenarios" }
```

Pin Crucible to the same commit in the harness as in this crate's `Cargo.toml`.
For complete examples, see `../targets/token_vault` and `../targets/raydium_cp_swap`.

## Roadmap

1. More mint profiles: default-account-state frozen, pausable, and a
   mint-close authority.
2. A deployable transfer-hook mock, so a harness can test hook *handling* as
   well as hook *rejection*.
3. Malicious mock CPI programs that return wrong data or re-enter the caller.
4. Invariant templates for the remaining protocol types: lending, escrow.
5. Compute-unit feedback for the fuzzer. Today the compute profile records what
   the coverage-guided search happens to reach; Crucible has no hook for
   steering the search toward expensive inputs.
