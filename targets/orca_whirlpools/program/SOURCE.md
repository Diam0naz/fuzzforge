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

Commit `822f213` ("Pinocchio Base and Liquidity Ops", 2026-01-30) moved
`increase_liquidity`, `decrease_liquidity` and their v2 variants to
hand-written Pinocchio handlers. Their Anchor handlers became
`unreachable!()` stubs, so a build of a later commit cannot run the Anchor
versions. (An earlier attempt here patched the routing table at HEAD; that
only sends those calls into the stubs, which panic. Do not use
`whirlpool_anchor_only.so` from that attempt.)

The reference is the commit just before the port:

- `whirlpool_71569ae.so`: the last Anchor implementation (2026-01-27).
- `whirlpool_822f213.so`: the port.

```sh
cd ~/src/targets/whirlpools
git fetch --deepen=400 origin        # the clone is shallow
OUT=~/Documents/Solana_Bootcamp/fuzzforge/targets/orca_whirlpools/program/reference
for c in 71569ae 822f213; do
  git worktree add -f ../whirlpools-$c $c
  (cd ../whirlpools-$c/programs/whirlpool && cargo build-sbf --tools-version v1.58 --features mainnet) \
    && cp ../whirlpools-$c/target/deploy/whirlpool.so "$OUT/whirlpool_$c.so"
done
sha256sum "$OUT"/whirlpool_71569ae.so "$OUT"/whirlpool_822f213.so
```

Then, from `targets/orca_whirlpools`:

```sh
FF_PROGRAM_SO=program/reference/whirlpool_822f213.so \
FF_DIFF_SO=program/reference/whirlpool_71569ae.so \
  crucible run -C . orca_whirlpools whirlpool_invariants --release --cores 4 --timeout 900
```

`reposition_liquidity_v2` and `increase_liquidity_by_token_amounts_v2`
arrived after the port and exist in neither build, so both builds reject
them alike. The diff covers the four ported instructions plus everything
else that changed in `822f213`.

Any `[upgrade-diff]` line is a case where the two builds disagree on an
instruction's outcome or on resulting account bytes. Each one is either an
intended change in that commit or a bug in the port. If it is a bug, it
goes to Orca's bug bounty on Immunefi (https://immunefi.com/bug-bounty/orca,
per the repository's SECURITY.md) and stays private.
