#!/usr/bin/env bash
#
# Build a tiny, valid bundle for exercising intake without a real program.
# It is NOT a runnable Trident harness; the sandbox adapter will reject it at
# the build/run step. Use a real project to produce a real report.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/programs/demo/src" "$work/trident-tests/fuzz_tests/fuzz_0"

cat >"$work/Anchor.toml" <<'EOF'
[programs.localnet]
demo = "11111111111111111111111111111111"

[provider]
cluster = "Localnet"
wallet = "~/.config/solana/id.json"
EOF

cat >"$work/programs/demo/Cargo.toml" <<'EOF'
[package]
name = "demo"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib", "lib"]

[dependencies]
anchor-lang = "0.31.0"
EOF

cat >"$work/programs/demo/src/lib.rs" <<'EOF'
use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod demo {
    use super::*;

    pub fn initialize(_ctx: Context<Initialize>) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize {}
EOF

cat >"$work/trident-tests/Cargo.toml" <<'EOF'
[package]
name = "trident-tests"
version = "0.1.0"
edition = "2021"

[dependencies]
trident-svm = "0.12"
EOF

cat >"$work/trident-tests/fuzz_tests/fuzz_0/test_fuzz_0.rs" <<'EOF'
// Placeholder fuzz test. Replace with a real Trident harness before running.
#[init]
fn start(&mut self) {}

#[flow]
fn flow0(&mut self) {}
EOF

out="$repo_root/examples/sample-bundle.tar.gz"
tar -czf "$out" -C "$work" .
echo "wrote $out"
