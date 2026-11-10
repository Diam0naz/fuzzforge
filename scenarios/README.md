# fuzzforge-scenarios

Reusable hostile scenarios for [Crucible](https://github.com/asymmetric-research/crucible)
harnesses. Use this crate for the cases Crucible's `--mutate-accounts` engine
skips. Don't re-implement the account checks it already covers: owner, signer,
PDA, type tag, duplicate accounts, and accounts forwarded into a CPI.

| Module | Provides |
| --- | --- |
| `token2022` | `MintProfile` matrix (SPL Token, plain Token-2022, transfer fee, permanent delegate, transfer hook, freeze authority, non-transferable) created through the real token programs; `TokenEnv` with attacker helpers (`attacker_pull`, `attacker_freeze`); `read_token_account`, which handles extensions |
| `invariants` | `CustodyLedger` (a balance moves only through authorized flows, and tracks fee shortfall), `LivenessLog` (an exit or deposit that must succeed did succeed), `summarize_logs` |

**Pitfall this crate works around:** `TestContext::token_balance` decodes token
accounts with the classic SPL layout, and returns `0` for any Token-2022 account
that has extensions. Always use `token2022::read_token_account` instead.

To use it in a harness:

```toml
fuzzforge-scenarios = { path = "../../scenarios" }
```

Pin Crucible to the same commit in the harness as in this crate's `Cargo.toml`.
For a complete example, see `../targets/token_vault`.

## Roadmap

1. More mint profiles: default-account-state frozen, interest-bearing, pausable,
   and a mint-close authority.
2. A deployable transfer-hook mock, so a harness can test hook *handling* as
   well as hook *rejection*.
3. Malicious mock CPI programs that return wrong data or re-enter the caller.
4. Invariant templates for each protocol type: vault, AMM, lending, escrow.
