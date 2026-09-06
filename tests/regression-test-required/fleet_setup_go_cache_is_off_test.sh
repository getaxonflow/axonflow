#!/usr/bin/env bash
# Regression guard: a fleet job using actions/setup-go must set `cache: false`.
#
# WHY. `setup-go` DEFAULTS `cache` to true, and that default tars and uploads
# GOCACHE + GOMODCACHE in a `Post Setup Go` step. On this fleet both live PER
# SLOT on the host and persist between jobs, so the upload buys nothing - and
# it is not cheap:
#
#   run 34015282283, `Backend Tests (invpc mode)` on aws-ip-10-1-2-29-5
#     06:00:15 -> 06:15:17, cancelled at 15m02s against timeout-minutes: 15
#     steps 1-7 (checkout, setup, TESTS, coverage, upload) all SUCCESS
#     step 13 `Post Setup Go`: cancelled
#
# The work finished in ~1.6 minutes. The cache save was still running thirteen
# minutes later and took the job down with it; matrix siblings on other slots
# spent 10.7 and 13.7 minutes in the same step.
#
# THE DEFAULT IS THE DEFECT, WHICH IS WHY ABSENCE FAILS HERE. A job that simply
# omits `cache:` gets the upload, and nothing in the file says so. Eleven jobs
# had drifted that way against fifty-three that were already correct, so this
# is completing an existing convention rather than inventing one -
# unit-tests-standalone-modules and unit-tests-ee-modules in test.yml are the
# in-file precedent.
#
# NOT A CAP PROBLEM, and the distinction matters because the first instance of
# this was fixed the other way. `test.yml :: audit-coverage-gate` was given a
# bigger `timeout-minutes` when its `Post Set up Go` overran; the cap raise
# made the symptom rarer and left a ten-minute step that produces nothing.
# That job is in this list too, now fixed at the cause.
#
# HOSTED JOBS ARE OUT OF SCOPE, deliberately. A hosted runner is a fresh VM per
# job, so the cache is the only thing that makes it warm. Several hosted lanes
# here go further and keep a hand-rolled "rolling entry" (`cache: false` plus
# their own actions/cache step, #3685) - that pattern is FOR hosted runners and
# must not be copied onto the fleet, where the host is already warm.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

check() {
  python3 - "$1" <<'PY'
import glob, io, os, sys, yaml

root = sys.argv[1]
censused, problems = 0, []
for f in sorted(glob.glob(os.path.join(root, '.github/workflows/*.yml'))):
    try:
        d = yaml.safe_load(io.open(f, encoding='utf-8'))
    except Exception:
        continue
    if not isinstance(d, dict):
        continue
    for jn, j in (d.get('jobs') or {}).items():
        if not isinstance(j, dict):
            continue
        ro = j.get('runs-on')
        if not (isinstance(ro, list) and 'self-hosted' in ro):
            continue
        for s in (j.get('steps') or []):
            if not isinstance(s, dict) or 'actions/setup-go' not in str(s.get('uses', '')):
                continue
            censused += 1
            w = s.get('with') or {}
            # ABSENT is a violation: setup-go's default is true.
            if w.get('cache', True) not in (False, 'false'):
                where = '%s:%s' % (os.path.basename(f), jn)
                how = 'cache: %r' % w['cache'] if 'cache' in w else 'no cache key (defaults to true)'
                problems.append('%s\t%s' % (where, how))
print(censused)
for p in problems:
    print(p)
PY
}

out=$(check .) || { echo "FAIL: the census did not run"; exit 1; }
censused=$(printf '%s\n' "$out" | head -1)
problems=$(printf '%s\n' "$out" | tail -n +2 | sed '/^$/d')

# Anti-vacuity on the EXAMINED population. Was 40 against 64 steps; the
# release-window pin (#3791) moved the 66 runtime-e2e suite jobs to
# ubuntu-latest, leaving 16 fleet setup-go steps, so a floor of 40 fails on a
# tree that is correct. 12 still catches a scan that has stopped reading the
# fleet, which is all this floor is for. THE REVERT RESTORES BOTH TOGETHER:
# `git revert` of that PR puts the suites back on the fleet and this floor
# back to 40 in the same commit.
if [ "${censused:-0}" -lt 12 ]; then
  echo "FAIL: only ${censused:-0} fleet setup-go steps censused (floor 40) - not reading the tree"
  exit 1
fi
echo "ok: censused ${censused} fleet setup-go step(s)"

if [ -n "$problems" ]; then
  echo "FAIL: fleet job(s) let setup-go upload a cache the host already has:"
  printf '%s\n' "$problems" | sed 's/^/  /'
  echo ""
  echo "GOCACHE and GOMODCACHE are per slot on this host and persist between"
  echo "jobs, so the Post Setup Go upload produces nothing and has killed a job"
  echo "at its timeout with every test already green. Set:"
  echo ""
  echo "    - uses: actions/setup-go@v6"
  echo "      with:"
  echo "        go-version: '1.25'"
  echo "        cache: false"
  echo ""
  echo "Raising timeout-minutes instead makes the symptom rarer and keeps the"
  echo "ten-minute step. On ubuntu-latest the cache is correct and this rule"
  echo "does not apply."
  exit 1
fi
echo "ok: every fleet setup-go step disables the cache"

# ---------------------------------------------------------------------------
# Controls, on a copy of the real tree.
# ---------------------------------------------------------------------------
tmp=$(mktemp -d) || exit 1
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/.github"

# CONTROL 1 - flip one back to true -> named.
cp -R .github/workflows "$tmp/.github/workflows"
python3 - "$tmp" <<'MUT'
import io, re, sys
p = sys.argv[1] + '/.github/workflows/test-customer-portal-modes.yml'
s = io.open(p, encoding='utf-8').read()
s2 = s.replace('          cache: false\n', '          cache: true\n', 1)
assert s2 != s, 'fixture: no cache: false line to flip'
io.open(p, 'w', encoding='utf-8').write(s2)
MUT
c1=$(check "$tmp" | tail -n +2 | grep -c 'test-customer-portal-modes.yml:')
[ "$c1" -ge 1 ] && echo "ok: cache: true on a fleet job IS caught" || {
  echo "FAIL: an explicit cache: true went unnoticed"; exit 1; }

# CONTROL 2 - the one that matters: DELETE the key, so the default applies.
# A guard that only looked for `cache: true` would pass this while the job
# uploads the cache exactly as before.
rm -rf "$tmp/.github/workflows"; cp -R .github/workflows "$tmp/.github/workflows"
python3 - "$tmp" <<'MUT'
import io, sys
p = sys.argv[1] + '/.github/workflows/test-customer-portal-modes.yml'
s = io.open(p, encoding='utf-8').read()
s2 = s.replace('          cache: false\n', '', 1)
assert s2 != s, 'fixture: no cache: false line to delete'
io.open(p, 'w', encoding='utf-8').write(s2)
MUT
c2=$(check "$tmp" | tail -n +2 | grep -c 'no cache key (defaults to true)')
[ "$c2" -ge 1 ] && echo "ok: an ABSENT cache key IS caught (the default is the defect)" || {
  echo "FAIL: omitting the key passed - the guard only sees an explicit true"
  check "$tmp" | tail -n +2 | head -3; exit 1; }

# CONTROL 3 - a HOSTED job with the cache on must NOT be flagged.
rm -rf "$tmp/.github/workflows"; cp -R .github/workflows "$tmp/.github/workflows"
cat > "$tmp/.github/workflows/hosted-fixture.yml" <<'Y'
on: push
jobs:
  hosted-go:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-go@v6
        with:
          go-version: '1.25'
          cache: true
Y
c3=$(check "$tmp" | tail -n +2 | grep -c 'hosted-fixture.yml')
[ "$c3" = "0" ] && echo "ok: a hosted job with the cache on is correctly out of scope" || {
  echo "FAIL: fired on ubuntu-latest, where the cache is what makes it warm"; exit 1; }

echo "PASS: no fleet job pays to upload a cache its host already has"
