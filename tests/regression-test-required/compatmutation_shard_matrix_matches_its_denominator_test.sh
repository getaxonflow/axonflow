#!/usr/bin/env bash
# #3976: the compatmutation mutation gate is split across CI shards. The
# partition itself is guarded in Go (TestTheShardPartitionCoversEveryMutantExactlyOnce),
# which proves that for any N the shards cover the population exactly once.
#
# THIS GUARD COVERS THE HALF GO CANNOT SEE: whether the WORKFLOW actually runs
# all N of them. The Go guard is a statement about `k/N`; the workflow chooses
# both the matrix list and the N in the env string, in two different places,
# and nothing ties them together. Edit the list to [1, 2] and leave the env at
# "/4" and half the mutants never run - every leg green, the job green, the
# aggregate green, and the population silently halved. That is the same
# silent-drop shape the Go guard exists to prevent, one level up.
set -uo pipefail

# NOT ON THE COMMUNITY MIRROR. This guard's SUBJECT is .github/workflows/
# test.yml, which the sync strips; this .sh is not stripped, so on the staged
# mirror tree it would run, hard-fail on a missing file, fail run-all.sh, and
# red the sync PR. Same convention and same reason as
# fleet_setup_go_cache_is_off_test.sh:65.
#
# KEYED ON ee/, NOT ON THE FILE'S ABSENCE. "test.yml is missing" is the
# community mirror's normal state and the enterprise tree's DEFECT - a skip
# keyed on the absence would silence exactly the case this guard exists for.
# ee/ is excluded by the sync by design, so its absence identifies the tree.
if [ ! -d ee ]; then
  echo "SKIP: no ee/ - community mirror tree, where .github/workflows/test.yml is not synced"
  exit 0
fi

WF=".github/workflows/test.yml"
name="compatmutation_shard_matrix_matches_its_denominator"
fail=0
pass() { echo "  PASS: $1"; }
flunk() { echo "  FAIL: $1"; fail=1; }

[ -f "$WF" ] || { echo "FAIL: $WF not found"; exit 1; }

# The matrix list, e.g. "shard: [1, 2, 3, 4]"
list=$(grep -oE '^ *shard: *\[[0-9, ]+\]' "$WF" | head -1 | sed -E 's/.*\[([0-9, ]+)\].*/\1/' | tr -d ' ')
# The denominator, from COMPATMUTATION_SHARD: "${{ matrix.shard }}/N"
denom=$(grep -oE 'COMPATMUTATION_SHARD: *"\$\{\{ *matrix\.shard *\}\}/[0-9]+"' "$WF" | grep -oE '/[0-9]+"' | tr -d '/"' | head -1)

if [ -z "$list" ]; then flunk "no 'shard: [...]' matrix found in $WF"; fi
if [ -z "$denom" ]; then flunk "no COMPATMUTATION_SHARD denominator found in $WF"; fi
[ "$fail" = "0" ] || { echo "RESULT: FAIL"; exit 1; }

count=$(echo "$list" | tr ',' '\n' | grep -c .)
if [ "$count" = "$denom" ]; then
  pass "matrix has $count shards and the denominator is /$denom"
else
  flunk "matrix has $count shards but COMPATMUTATION_SHARD says /$denom - $((denom - count)) shard(s) of the population would never run, with every leg green"
fi

expected=$(seq 1 "$denom" | paste -sd, -)
if [ "$list" = "$expected" ]; then
  pass "matrix is exactly 1..$denom ($list)"
else
  flunk "matrix is [$list] but must be exactly 1..$denom ([$expected]) - a gap or duplicate silently drops or repeats a shard"
fi

if [ "$fail" = "0" ]; then echo "PASS: $name"; else echo "RESULT: FAIL"; exit 1; fi
