# Orca Whirlpools binaries

Program `whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc`. Orca Whirlpools is
licensed under Apache 2.0. The binaries are used unmodified for local fuzzing
only and are not committed: dump or build them with the commands below.

## Deployed build (default target)

```sh
solana program dump -u mainnet-beta whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc \
  program/whirlpool_mainnet_2026-11-11.so
```

The dump taken on 2026-11-11 has sha256
`c422b22f3eefe86dd55878a4f505b9c68c26e241dc96af1573ca032b24b8ee3f`
(10,485,715 bytes, including program-data padding).

## Pinocchio port against the Anchor original (upgrade-diff)

The deployed program sends six liquidity instructions to hand-written
Pinocchio ports (`programs/whirlpool/src/entrypoint.rs`). The Anchor versions
of the same six are still in the source. Two builds of one commit isolate
the port:

- `whirlpool_pinocchio.so`: the source as is.
- `whirlpool_anchor_only.so`: the same source with `anchor-only.patch`
  applied. It empties the routing table, so every instruction runs through
  Anchor; nothing else changes.

Source: [orca-so/whirlpools](https://github.com/orca-so/whirlpools) at
`cc683ec92acb5e7606caa3d8e514d9383e9c7c11`.

```sh
cd ~/src/targets/whirlpools/programs/whirlpool
OUT=~/Documents/Solana_Bootcamp/fuzzforge/targets/orca_whirlpools/program/reference
mkdir -p "$OUT"

cargo build-sbf --tools-version v1.58 --features mainnet
cp ../../target/deploy/whirlpool.so "$OUT/whirlpool_pinocchio.so"

git apply "$OUT/../anchor-only.patch"
cargo build-sbf --tools-version v1.58 --features mainnet
cp ../../target/deploy/whirlpool.so "$OUT/whirlpool_anchor_only.so"
git checkout src/entrypoint.rs

sha256sum "$OUT"/*.so
```

Then, from `targets/orca_whirlpools`:

```sh
FF_PROGRAM_SO=program/reference/whirlpool_pinocchio.so \
FF_DIFF_SO=program/reference/whirlpool_anchor_only.so \
  crucible run -C . orca_whirlpools whirlpool_invariants --release --cores 4 --timeout 900
```

Any `[upgrade-diff]` line is a case where the Pinocchio port and the Anchor
original disagree on an instruction's outcome or on resulting account
bytes. Each one is either an intended change or a bug in the port. If it is
a bug, it goes to Orca's bug bounty on Immunefi
(https://immunefi.com/bug-bounty/orca, per the repository's SECURITY.md) and
stays private.
