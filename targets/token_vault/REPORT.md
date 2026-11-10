# Fuzzforge report: `token_vault` × Token-2022 hostile mint matrix

| | |
| --- | --- |
| Program | `token_vault` (Anchor 0.32.1), program id `5T3ha5hsysKo23gvCzREqAsotWwKq9SMRShZ6iLhZBS7` |
| Binary | `program/token_vault.so`, sha256 `90b5355bbce97ad4a32b11350fc186c9ad5719577bd3556a7b17a8b126af3abe` |
| Engine | Crucible `26c23914548035d51b86e885e86f5e3ebafb88ee` (LiteSVM 0.15.2, Token-2022 v11) |
| Campaigns | 90 s invariant campaign, 34,986 executions; 60 s `--mutate-accounts` campaign, 21,930 executions; single core |
| Date | 2026-11-10 |

**Scope statement.** This report lists what failed under the conditions below.
A property that did not fail was not proven to hold. This is not an audit and
not a statement that the program is secure.

## Summary

`token_vault` takes any mint whose owner is SPL Token or Token-2022, and checks
no Token-2022 extensions. Five of the seven mint profiles tested break at least
one property. The two control profiles (classic SPL Token, and Token-2022 with
no extensions) broke nothing. That shows the findings come from extension
handling, not from the harness.

| ID | Finding | Mint profile | Property | Steps to reproduce |
| --- | --- | --- | --- | --- |
| F1 | Vault can never be closed after any deposit | transfer fee | exit liveness | 2 |
| F2 | Third party drains vault without the owner's signature | permanent delegate | custody | 2 |
| F3 | Third party locks vault funds indefinitely | freeze authority | exit liveness | 3 |
| F4 | `initialize` accepts the mint, but every deposit fails | transfer hook | deposit liveness | preflight |
| F5 | `initialize` accepts the mint, but every deposit fails | non-transferable | deposit liveness | preflight |
| T1 | `[CC-13 forwarded-account]` on `close`: needs triage, likely a false positive | all | account validation | — |

How severe each finding is depends on who picks the mint. In `token_vault`, the
vault owner picks it, so F2 and F3 need a mint issuer who is malicious or
compromised. In a program where one party picks the mint and another deposits
into it (pools, escrows, lending markets), the same patterns are critical.

## Properties checked

* **Custody:** a vault's balance changes only through the owner's `deposit` and
  `withdraw`. Expected balances come from the balance changes observed on those
  calls, so a fee taken on deposit is not counted as a violation.
* **Exit liveness:** from any reachable state, the owner can withdraw the full
  balance and then `close`.
* **Deposit liveness:** a deposit no larger than the owner's unfrozen balance
  succeeds.
* **Lifecycle:** `initialize` fails on a live vault. Never violated.

Attacker model: one keypair that holds every privileged mint authority other
than the mint authority itself: permanent delegate, freeze authority, and
transfer-fee authorities. It has no other privileges.

## Findings

### F1: Transfer-fee mint: the vault can never be closed

```
1. deposit(amount=3672454, mint=transfer-fee) -> OK
2. owner_exit(mint=transfer-fee)              -> FAIL
   withdraw(3635729) OK, then close: Token-2022 error 0x23 AccountHasWithheldTransferFees
   vault amount 0, withheld fees 36725
```

Every deposit leaves 1% in the vault as *withheld* fees, which are not part of
`amount`. `close` checks `vault.amount == 0`, so the check passes. The
`close_account` CPI then fails, because Token-2022 will not close an account
that still holds withheld fees. The program has no instruction that harvests or
withdraws those fees, so the vault and the rent in `vault_state` stay locked for
good.

**Fix:** in `close`, before `close_account`, CPI
`harvest_withheld_tokens_to_mint` for the vault. Anyone can call it. Or reject
mints that have `TransferFeeConfig` in `initialize`.

### F2: Permanent-delegate mint: a third party drains the vault

```
1. deposit(amount=1, mint=permanent-delegate) -> OK
2. attacker transfer_checked(vault -> attacker, 40%), signed only by the delegate -> OK
   custody: balance 0 != expected 1
```

A permanent delegate can move tokens out of any account of that mint, including
the vault ATA owned by the PDA. `token_vault` has no way to stop this once it
has accepted the mint.

**Fix:** in `initialize`, reject mints that have `PermanentDelegate`, unless
custody of issuer-controlled assets is an intended feature that you document.

### F3: Mint with a freeze authority: a third party locks funds

```
1. deposit(amount=3, mint=freeze-authority) -> OK
2. attacker freeze_account(vault)           -> OK
3. owner_exit                               -> FAIL: withdraw: token error 0x11 AccountFrozen
```

**Fix:** reject mints with a `freeze_authority` in `initialize`, or document
that the issuer can freeze balances held in vaults. This also applies to classic
SPL Token mints: USDC, for example, has a freeze authority.

### F4 and F5: Mints accepted at initialize that can never be deposited

* **Transfer hook:** `deposit` calls `transfer_checked` without the hook program
  or its extra account metas, so it always fails with "An account required by
  the instruction is missing".
* **Non-transferable:** every transfer fails with Token-2022 error `0x25`
  NonTransferable.

No funds are lost: rent is spent creating vaults that can never be used. **Fix:**
reject these mints in `initialize`, or support transfer hooks by resolving the
extra account metas (`spl-transfer-hook-interface`) and passing them as
remaining accounts.

### T1: `[CC-13 forwarded-account]` on `close` (triage)

Crucible's constraint engine replaced an account that `close` passes into the
Token-2022 `CloseAccount` CPI with a malformed one, and the call still
succeeded. The likely account is `owner`, which only receives the rent
lamports. Crucible's own documentation lists a "by-design-arbitrary transfer
recipient" as a known false positive for this probe. This needs manual
confirmation before it is reported as a finding.

## Recommended single fix

Add an extension allowlist to `initialize`. Read the mint with
`StateWithExtensions::<Mint>`, reject any extension type you have not designed
for, and reject a `freeze_authority` unless you accept it on purpose. That one
check removes F2 through F5. F1 still needs the harvest-before-close change if
you want to support fee-bearing mints.

## Reproduction

Requires the Crucible CLI built from the commit above, and Rust 1.89 or later.

```bash
cd targets/token_vault

# replay a minimized finding (F1, F2, F3)
crucible show -C . token_vault F1-transfer-fee-close-blocked --replay --crashes-dir findings

# full campaign
crucible run -C . token_vault token2022_matrix --release --timeout 90

# add Crucible's account-constraint probes
crucible run -C . token_vault token2022_matrix --release --timeout 60 --mutate-accounts
```

Preflight findings (F4, F5) are printed as `[FF_PREFLIGHT]` lines at the start
of every run.

## Coverage and limits

* sBPF edge coverage reached 34.6% of edges across the loaded programs. Most of
  the edges not reached are inside Token-2022 code paths that this program never
  calls.
* Not tested: Token-2022 extensions outside the seven profiles listed (for
  example interest-bearing, pausable, confidential transfer, and
  default-account-state frozen), multiple vault owners, and calls made through
  another program (CPI depth and compute limits).
