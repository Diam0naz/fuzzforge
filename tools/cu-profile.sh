#!/usr/bin/env bash
# Merge the compute-unit profiles a campaign wrote with FF_CU_OUT=<dir>
# (one cu-<pid>.tsv per fuzzer worker) into one table: the highest compute
# units seen per build, instruction and lane, highest first.
#
#   FF_CU_OUT=cu crucible run -C targets/<t> <program> <test> --release --timeout 600
#   tools/cu-profile.sh targets/<t>/cu            # full table
#   tools/cu-profile.sh targets/<t>/cu --by-ix    # worst lane per instruction
#
# In upgrade-diff mode (FF_DIFF_SO) both builds are profiled; --regressions
# lists the instructions whose worst case costs more on the candidate build.
set -euo pipefail
dir=${1:?usage: cu-profile.sh <FF_CU_OUT dir> [--by-ix|--regressions]}
mode=${2:-}
shopt -s nullglob
files=("$dir"/cu-*.tsv)
[ ${#files[@]} -gt 0 ] || { echo "no cu-*.tsv files in $dir" >&2; exit 1; }
limit=${FF_CU_LIMIT:-200000}

merged=$(cat "${files[@]}" | awk -F'\t' '{k=$2 FS $3 FS $4; if ($1+0 > m[k]) m[k]=$1+0} END {for (k in m) print m[k] FS k}' | sort -t$'\t' -k1,1nr)

case "$mode" in
  --by-ix)
    printf 'units\t%%limit\tbuild\tinstruction\tworst lane\n'
    echo "$merged" | awk -F'\t' -v L="$limit" '!seen[$2 FS $3]++ {printf "%d\t%.0f%%\t%s\t%s\t%s\n", $1, 100*$1/L, $2, $3, $4}'
    ;;
  --regressions)
    printf 'candidate\treference\tdelta\tinstruction\n'
    echo "$merged" | awk -F'\t' '{if ($1+0 > m[$2 FS $3]) m[$2 FS $3]=$1+0; ix[$3]=1}
      END {for (i in ix) {c=m["candidate" FS i]; r=m["reference" FS i]; if (c && r && c != r) printf "%d\t%d\t%+d\t%s\n", c, r, c-r, i}}' | sort -t$'\t' -k3,3nr
    ;;
  "")
    printf 'units\t%%limit\tbuild\tinstruction\tlane\n'
    echo "$merged" | awk -F'\t' -v L="$limit" '{printf "%d\t%.0f%%\t%s\t%s\t%s\n", $1, 100*$1/L, $2, $3, $4}'
    ;;
  *) echo "unknown option $mode" >&2; exit 1 ;;
esac
