# raydium_cp_swap.so

Built locally from https://github.com/raydium-io/raydium-cp-swap at commit
`3d69122790e97cd6aff24e8ba95940793773f58c` with
`cargo build-sbf --tools-version v1.58`, default features (mainnet program id).

sha256 `1cf5ce07c1c019316da0e47069d584ad48d2290f0c814e170a7949e8bfe89609`

Raydium CP-Swap is licensed under the Apache License 2.0; this binary is
redistributed unmodified for local fuzzing only.

## Reference builds for upgrade-diff runs

`reference/` is not committed. To diff the local build against the program
deployed on mainnet:

```sh
mkdir -p program/reference
solana program dump -u mainnet-beta CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C \
  program/reference/cp_swap_mainnet_<date>.so
FF_DIFF_SO=program/reference/cp_swap_mainnet_<date>.so \
  crucible run -C . raydium_cp_swap amm_invariants --release --timeout 900
```

The dump taken on 2026-11-11 has sha256
`c383e1c5b1f578f3d1bf42f12360fca67225b9adda0f3b6c293ad0d6b966818d`
(793,824 bytes including the program-data padding). It is a different binary
from the local build above; the two were compiled with different toolchains.
