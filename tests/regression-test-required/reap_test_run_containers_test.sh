#!/usr/bin/env bash
# Regression test for scripts/ci/reap-test-run-containers.sh (#4184).
#
# The reaper removes the test containers ONE run started and nothing else.
# This drives it against a fake `docker` on PATH that holds a table of
# containers and records every removal, so each property is observed from what
# the script DID, not read from its source:
#
#   1. no run id: exit 2, a sentence naming AXONFLOW_TEST_RUN_ID, and docker is
#      never called (no fallback to the bare ephemeral label);
#   2. a malformed run id: exit 2, docker never called;
#   3. a run's containers are removed, with -fv, and each is logged; a
#      container of ANOTHER run and one with NO run label are left, and the log
#      counts both;
#   4. a second run finds nothing, removes nothing and exits 0 (a trap can fire
#      twice);
#   5. a removal that fails exits 1 and says so.
#
# The same behaviour against a real daemon (a killed test leaving a labelled
# container) is proven on the slot, not here: this file runs container-free.
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
reaper="$repo_root/scripts/ci/reap-test-run-containers.sh"
work="$(mktemp -d "${TMPDIR:-/tmp}/reap-test-run.XXXXXX")"
trap 'rm -rf "$work"' EXIT
echo "work dir: $work"
fails=0
pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; fails=$((fails + 1)); }

# The fake docker. $work/containers holds one line per container:
#   <id> <name> <run label or -> <ephemeral 1 or -> [<owner label or ->]
# Every invocation is appended to $work/calls; `rm` deletes the line unless the
# id is listed in $work/rm-fails.
mkdir -p "$work/bin"
cat > "$work/bin/docker" <<'SHIM'
#!/usr/bin/env bash
W="$FAKE_DOCKER_WORK"
echo "$*" >> "$W/calls"
case "$1" in
  ps)
    [ -e "$W/ps-fails" ] && { echo "fake docker: Cannot connect to the Docker daemon" >&2; exit 1; }
    filter="${@: -1}"
    case "$filter" in
      label=axonflow.test.run=*) want="${filter#label=axonflow.test.run=}"
        awk -v w="$want" '$3 == w {print $1}' "$W/containers" ;;
      label=axonflow.test.ephemeral=1)
        awk '$4 == "1" {print $1}' "$W/containers" ;;
      *) echo "fake docker: unexpected filter $filter" >&2; exit 9 ;;
    esac ;;
  inspect)
    id="${@: -1}"
    line=$(awk -v i="$id" '$1 == i' "$W/containers")
    case "$3" in
      *Name*) echo "/$(echo "$line" | awk '{print $2}')" ;;
      *axonflow.test.owner*) o=$(echo "$line" | awk '{print $5}'); [ -z "$o" ] || [ "$o" = "-" ] || echo "$o" ;;
      *axonflow.test.run*) r=$(echo "$line" | awk '{print $3}'); [ "$r" = "-" ] || echo "$r" ;;
    esac ;;
  rm)
    [ "$2" = "-fv" ] || { echo "fake docker: rm without -fv" >&2; exit 9; }
    grep -qx "$3" "$W/rm-fails" 2>/dev/null && exit 1
    awk -v i="$3" '$1 != i' "$W/containers" > "$W/c.tmp" && mv "$W/c.tmp" "$W/containers" ;;
  info) exit 0 ;;
  *) echo "fake docker: unexpected $1" >&2; exit 9 ;;
esac
SHIM
chmod +x "$work/bin/docker"
export FAKE_DOCKER_WORK="$work"
run() { PATH="$work/bin:$PATH" bash "$reaper" "$@" > "$work/out" 2>&1; }

# 1. No run id.
: > "$work/calls"; printf 'aaa1 pg-a runA 1\n' > "$work/containers"
run; rc=$?
if [ "$rc" = 2 ] && grep -q 'AXONFLOW_TEST_RUN_ID' "$work/out" && [ ! -s "$work/calls" ]; then
  pass "no run id: exit 2, names AXONFLOW_TEST_RUN_ID, docker never called"
else
  fail "no run id: rc=$rc calls=$(tr '\n' ';' < "$work/calls") out=$(cat "$work/out")"
fi

# 2. A malformed run id.
: > "$work/calls"
run 'bad id;rm'; rc=$?
if [ "$rc" = 2 ] && [ ! -s "$work/calls" ]; then
  pass "malformed run id: exit 2, docker never called"
else
  fail "malformed run id: rc=$rc calls=$(tr '\n' ';' < "$work/calls")"
fi

# 3. This run's two containers go; another run's and an unlabelled one stay.
: > "$work/calls"
printf '%s\n' 'aaa1 pg-a runA 1' 'aaa2 pg-b runA 1' 'bbb1 pg-peer runB 1' 'ccc1 pg-bare - 1' > "$work/containers"
run runA; rc=$?
left=$(awk '{print $1}' "$work/containers" | sort | tr '\n' ' ')
if [ "$rc" = 0 ] && [ "$left" = "bbb1 ccc1 " ] \
   && grep -q 'removed pg-a' "$work/out" && grep -q 'removed pg-b' "$work/out" \
   && grep -q 'removed 2, failed 0; left 1 ephemeral container(s) labelled with another run and 1 with no run label' "$work/out"; then
  pass "run A's containers removed with -fv and logged; the peer's and the unlabelled one left and counted"
else
  fail "run A: rc=$rc left='$left' out=$(cat "$work/out")"
fi
if grep -q 'bbb1\|ccc1' <(grep '^rm' "$work/calls"); then
  fail "a container that is not run A's was passed to docker rm: $(grep '^rm' "$work/calls" | tr '\n' ';')"
else
  pass "docker rm was never called on another run's or an unlabelled container"
fi

# 4. The trap fires twice: the second run finds nothing.
run runA; rc=$?
if [ "$rc" = 0 ] && grep -q 'removed 0, failed 0' "$work/out"; then
  pass "a second run removes nothing and exits 0"
else
  fail "second run: rc=$rc out=$(cat "$work/out")"
fi

# 5. A removal that fails is an exit 1, named.
printf '%s\n' 'ddd1 pg-stuck runC 1' > "$work/containers"; echo ddd1 > "$work/rm-fails"
run runC; rc=$?
if [ "$rc" = 1 ] && grep -q 'FAILED to remove pg-stuck' "$work/out"; then
  pass "a failed removal exits 1 and names the container"
else
  fail "failed removal: rc=$rc out=$(cat "$work/out")"
fi

# 6. --dead-owners: only a container on this host whose owner process is gone.
host=$(hostname)
( exit 0 ) & deadpid=$!
wait "$deadpid"
printf '%s\n' \
  "eee1 pg-dead - 1 ${host}:${deadpid}" \
  "eee2 pg-live - 1 ${host}:$$" \
  "eee3 pg-otherhost - 1 other-host.example:${deadpid}" \
  "eee4 pg-noowner - 1 -" > "$work/containers"
: > "$work/rm-fails"; : > "$work/calls"
run --dead-owners; rc=$?
left=$(awk '{print $1}' "$work/containers" | sort | tr '\n' ' ')
if [ "$rc" = 0 ] && [ "$left" = "eee2 eee3 eee4 " ] \
   && grep -q "removed pg-dead" "$work/out" \
   && grep -q "removed 1, failed 0; left 1 with a running owner, 1 owned by another host and 1 with no readable owner label" "$work/out"; then
  pass "--dead-owners removes only the container whose owner on this host is gone; a live owner's, another host's and an unowned one stay"
else
  fail "--dead-owners: rc=$rc left='$left' out=$(cat "$work/out")"
fi
run --dead-owners; rc=$?
if [ "$rc" = 0 ] && grep -q "removed 0, failed 0" "$work/out"; then
  pass "--dead-owners run again removes nothing and exits 0"
else
  fail "--dead-owners second run: rc=$rc out=$(cat "$work/out")"
fi

# 6b. An owner label this script cannot read (host:notapid) is left, and
#     counted with the unreadable ones: never guessed at.
printf '%s\n' "ggg1 pg-garbled - 1 ${host}:notapid" > "$work/containers"; : > "$work/calls"
run --dead-owners; rc=$?
if [ "$rc" = 0 ] && grep -q '^ggg1 ' "$work/containers" && ! grep -q '^rm' "$work/calls" \
   && grep -q "removed 0, failed 0; left 0 with a running owner, 0 owned by another host and 1 with no readable owner label" "$work/out"; then
  pass "--dead-owners leaves a container whose owner label is unreadable, and counts it"
else
  fail "--dead-owners with a malformed owner: rc=$rc left=$(awk '{print $1}' "$work/containers" | tr '\n' ' ') out=$(cat "$work/out")"
fi

# 6c. docker ps failing is an exit 1 that removes NOTHING, in both modes.
printf '%s\n' "hhh1 pg-dead - 1 ${host}:${deadpid}" 'hhh2 pg-run runH 1 -' > "$work/containers"
touch "$work/ps-fails"
for mode in --dead-owners runH; do
  : > "$work/calls"
  run "$mode"; rc=$?
  if [ "$rc" = 1 ] && ! grep -q '^rm' "$work/calls" && grep -q 'docker ps failed; nothing was removed' "$work/out"; then
    pass "a failing docker ps in mode $mode exits 1 and removes nothing"
  else
    fail "failing docker ps in mode $mode: rc=$rc calls=$(tr '\n' ';' < "$work/calls") out=$(cat "$work/out")"
  fi
done
rm -f "$work/ps-fails"

# 7. run-all reaps only a run id it minted: an inherited id is its caller's.
fixture="$work/suite"; mkdir -p "$fixture"
printf '#!/usr/bin/env bash\nexit 0\n' > "$fixture/ok_test.sh"
printf '%s\n' 'fff1 pg-parent parentrun 1 -' > "$work/containers"; : > "$work/calls"
PATH="$work/bin:$PATH" AXONFLOW_TEST_RUN_ID=parentrun REGRESSION_SUITE_DIR="$fixture" bash "$repo_root/tests/regression-test-required/run-all.sh" > "$work/runall-out" 2>&1
if grep -q 'label=axonflow.test.run=parentrun' "$work/calls" || ! grep -q '^fff1 ' "$work/containers"; then
  fail "a run-all that inherited its run id reaped its caller's run: calls=$(tr '\n' ';' < "$work/calls")"
else
  pass "a run-all that inherited its run id leaves its caller's containers"
fi
# The trap's --dead-owners call is asserted by what it REMOVES, not by the
# filter it issues: the run-id path issues the same ephemeral filter for its
# own summary, so a grep on the call would pass with --dead-owners deleted.
printf '%s\n' "iii1 pg-dead-owner - 1 ${host}:${deadpid}" 'iii2 pg-peer-run otherrun 1 -' > "$work/containers"; : > "$work/calls"
PATH="$work/bin:$PATH" AXONFLOW_TEST_RUN_ID='' REGRESSION_SUITE_DIR="$fixture" bash "$repo_root/tests/regression-test-required/run-all.sh" > "$work/runall-out" 2>&1
if grep -q 'label=axonflow.test.run=run-all-' "$work/calls" && ! grep -q '^iii1 ' "$work/containers" && grep -q '^iii2 ' "$work/containers"; then
  pass "a run-all that minted its run id reaps that run and removes a dead owner's container, leaving another run's"
else
  fail "a minted run-all did not reap its run and the dead owners: left=$(awk '{print $1}' "$work/containers" | tr '\n' ' ') calls=$(tr '\n' ';' < "$work/calls")"
fi

if [ "$fails" -ne 0 ]; then
  echo "FAIL: reap_test_run_containers ($fails)"
  exit 1
fi
echo "PASS: reap_test_run_containers"
