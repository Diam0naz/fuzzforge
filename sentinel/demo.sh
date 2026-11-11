#!/usr/bin/env bash
# Sentinel end to end on mainnet, in about five minutes. Read-only: nothing is
# sent to the cluster. Set SENTINEL_RPC to use your own endpoint; the public
# one rate-limits.
#
#   ./demo.sh                 # every step
#   ./demo.sh drill trace     # chosen steps
set -euo pipefail
cd "$(dirname "$0")"
cargo build --release -q
B=target/release/sentinel
CP=policies/raydium-cp-swap.toml
SP=policies/spl-stake-pool.toml
CP_POOL=54GtpHJaEGKsfq6pWSRJa656zRgVFhkC5fzQBmp7qXmS     # Raydium CP-Swap pool
JITO=Jito4APyf642JPZPx3hGc6WWJ8zPKtRbRs4P815Awbb        # JitoSOL stake pool
CP_AUTHORITY=GpMZbSM2GgvTKHJirzeGfMFoaZ8UR2X7F4v8vHTvxFbL # CP-Swap vault authority
OUT=${DEMO_OUT:-$(mktemp -d)}
mkdir -p "$OUT"
quiet() { grep -v -E '^\[(COVERAGE|drill)\]' || true; }
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
want() { [ $# -eq 0 ] && return 0; for s in "${STEPS[@]}"; do [ "$s" = "$1" ] && return 0; done; return 1; }
STEPS=("$@")
[ ${#STEPS[@]} -eq 0 ] && STEPS=(policy drill watch trace)

if want policy; then
  step "1. The policy a reviewer reads (closed rule set, evidence per rule, sign-off state)"
  $B policy $CP
fi

if want drill; then
  step "2. Firewall drill: fresh transactions against a live CP-Swap pool, expected verdict per case"
  $B drill --policy $CP --pool $CP_POOL --candidate-so ../targets/raydium_cp_swap/program/raydium_cp_swap.so 2>&1 | quiet
  step "   Same engine, second protocol: SPL Stake Pool (JitoSOL)"
  $B drill --policy $SP --pool $JITO 2>&1 | quiet
fi

if want watch; then
  step "3. Monitor: three rounds on a live pool, one JSON line per finding"
  : > "$OUT/findings.jsonl"
  $B watch --policy $CP --pool $CP_POOL --rounds 3 --interval 10 --out "$OUT/findings.jsonl" 2> "$OUT/watch.log"
  grep '^\[sentinel\]' "$OUT/watch.log"
  echo "findings: $(wc -l < "$OUT/findings.jsonl") (in $OUT/findings.jsonl)"
fi

if want trace; then
  step "4. Incident response: follow value out of a recent swap, as if the pool had been drained"
  # The most recent transactions that moved value out of the pool authority (a swap).
  SIGS=$(curl -s "${SENTINEL_RPC:-https://api.mainnet-beta.solana.com}" -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getSignaturesForAddress\",\"params\":[\"$CP_POOL\",{\"limit\":60}]}" \
    | python3 -c 'import json,sys; r=[x["signature"] for x in json.load(sys.stdin)["result"] if not x["err"]]; print(" ".join(r[-10:]))')
  traced=
  for SIG in $SIGS; do
    if $B trace --signature "$SIG" --from $CP_AUTHORITY --hops 2 --max-tx 10 --report "$OUT/incident.md" > "$OUT/trace.json" 2> "$OUT/trace.log"; then
      traced=1; break
    fi
    echo "skipped ${SIG:0:12}…: $(tail -1 "$OUT/trace.log" | cut -c1-120)"
  done
  [ -n "$traced" ] || { echo "no recent transaction moved value out of the pool"; exit 1; }
  sed -n '1,25p' "$OUT/incident.md"
  echo "… full report: $OUT/incident.md"
fi
