#!/usr/bin/env bash
# Regression guard: a fleet job must not install an executable to a path
# that every runner slot shares.
#
# THE BUG CLASS, MEASURED TWICE ON 2026-09-05. Eight self-hosted runner slots
# share one host, so they share /home/runner and /usr. An installer that
# writes a fixed absolute path there is writing ONE file for all eight. Two
# jobs installing at once leave the loser exec'ing a partially written binary:
#
#     exit 126        ("cannot execute")
#
# Nothing in the log points at the cause - the same step passes on another
# slot in the same minute with the same pin, because the winner's file was
# complete. That is what ejected a merge-queue entry on
# `Trivy Scan - Orchestrator Docker Image`: one 160 MB
# /home/runner/.local/bin/trivy-bin/trivy for the whole host. The Trivy case
# is NOT fixable from a workflow (the action exposes `cache-dir` but no input
# for its binary path, so those five jobs are pinned to ubuntu-latest
# instead); the two this guard covers ARE:
#
#   lint.yml:golangci-lint         -b $(go env GOPATH)/bin  -> /home/runner/go/bin
#   regression-test-required.yml   npm install -g           -> /usr/lib/node_modules
#
# WHY THE GO ONE SURVIVED THE EARLIER PER-SLOT WORK: the slots' .env sets
# GOCACHE and GOMODCACHE per slot but NOT GOPATH, so `go env GOPATH` still
# answers $HOME/go. Naming two of a tool's three path variables leaves the
# third shared, and nothing complains.
#
# THE FIX SHAPE IS ALWAYS $RUNNER_TEMP, which the runner guarantees is private
# per job on hosted AND self-hosted runners - so it closes this axis without
# inventing a second isolation scheme that has to be kept in sync with the
# slot count.
#
# SCOPED TO THE FLEET ON PURPOSE. `npm install -g` is correct on
# ubuntu-latest, where the machine is destroyed after the job. A rule that
# fires on legitimate hosted usage is wrong and gets ignored, so there is a
# control below asserting it does NOT fire on a hosted job.
#
# ORDER MATTERS HERE, AND IT IS DELIBERATE: the fixture self-test runs FIRST,
# then the real tree. The usual anti-vacuity floor - "at least N fleet jobs
# censused" - cannot be used, because the fleet migration is still an open PR
# and this branch's tree has ZERO self-hosted jobs; a floor would fail on a
# tree that simply has nothing to check yet, and lowering it to 0 would make
# it meaningless. So the fixtures carry the whole anti-vacuity argument
# instead: they contain the two real offending lines this change removes, and
# if the matcher stops seeing THEM the guard fails here rather than reporting
# a confident zero over a tree it can no longer read.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

CENSUS=tests/regression-test-required/lib/fleet_shared_install_census.py
[ -f "$CENSUS" ] || { echo "FAIL: census helper missing: $CENSUS"; exit 1; }

# ONE matcher for the fixtures and for the repo. Two separately-anchored
# copies is how the host-ports guard silently skipped 32 declarations while
# reporting a confident zero.
run_census() { python3 "$CENSUS" "$1"; }

# ---------------------------------------------------------------------------
# PART 1 - prove the instrument, before trusting any verdict from it.
# ---------------------------------------------------------------------------
tmp=$(mktemp -d) || exit 1
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/.github/workflows"

# CONTROL 1 (known-bad): the two real lines this change replaces, verbatim.
cat > "$tmp/.github/workflows/kb.yml" <<'Y'
on: push
jobs:
  golangci-lint:
    runs-on: [self-hosted, linux, x64, axonflow]
    steps:
      - run: |
          curl -sSfL https://example.invalid/install.sh | sh -s -- -b $(go env GOPATH)/bin v2.11.4
  run-regression-suite:
    runs-on: [self-hosted, linux, x64, axonflow]
    steps:
      - run: |
          npm install -g "@apidevtools/swagger-cli@4.0.4"
  installs-with-go-install:
    runs-on: [self-hosted, linux, x64, axonflow]
    steps:
      - run: go install example.com/tool@v1.2.3
  installs-with-pip-user:
    runs-on: [self-hosted, linux, x64, axonflow]
    steps:
      - run: pip install --user some-tool==1.0.0
Y

# CONTROL 2: the same strings inside COMMENTS must not fire. This is not
# hypothetical - the change that removes these lines documents what it
# removed, so the forbidden text is back in both workflow files as prose. A
# matcher that reads raw file text calls a correct fix a violation, and that
# false verdict sends the next reader to "fix" working code.
cat > "$tmp/.github/workflows/comment.yml" <<'Y'
on: push
jobs:
  documented-fix:
    runs-on: [self-hosted, linux, x64, axonflow]
    steps:
      - run: |
          # NOT `npm install -g` and not -b $(go env GOPATH)/bin: both are
          # shared across slots. go install foo@v1 would be too, and so
          # would pip install --user.
          mkdir -p "$RUNNER_TEMP/bin"
          npm install --prefix "$RUNNER_TEMP/tool" "some-cli@1.0.0"
          echo "$RUNNER_TEMP/tool/node_modules/.bin" >> "$GITHUB_PATH"
Y

# CONTROL 3: identical commands on a HOSTED runner are correct and must pass.
cat > "$tmp/.github/workflows/hosted.yml" <<'Y'
on: push
jobs:
  hosted-install:
    runs-on: ubuntu-latest
    steps:
      - run: |
          npm install -g some-cli@1.0.0
          go install example.com/tool@v1.2.3
Y

fx=$(run_census "$tmp") || { echo "FAIL: census did not run on fixtures"; exit 1; }
fx_censused=$(printf '%s\n' "$fx" | head -1)
fx_hits=$(printf '%s\n' "$fx" | tail -n +2 | sed '/^$/d')

if [ "${fx_censused:-0}" -ne 5 ]; then
  echo "FAIL: fixture census saw ${fx_censused:-0} fleet jobs, expected 5"
  echo "      (the parser is not reading runs-on the way this guard assumes)"
  exit 1
fi

for expect in \
  "kb.yml:golangci-lint" \
  "kb.yml:run-regression-suite" \
  "kb.yml:installs-with-go-install" \
  "kb.yml:installs-with-pip-user"
do
  case "$fx_hits" in
    *"$expect"*) echo "ok: known-bad fixture ${expect} IS flagged" ;;
    *) echo "FAIL: the matcher missed known-bad fixture ${expect}"
       printf '%s\n' "$fx_hits" | sed 's/^/    /'
       exit 1 ;;
  esac
done

case "$fx_hits" in
  *comment.yml*)
    echo "FAIL: a rule fired on a shell COMMENT - a documented fix reads as a violation"
    printf '%s\n' "$fx_hits" | sed 's/^/    /'
    exit 1 ;;
  *) echo "ok: the forbidden text inside comments does NOT fire" ;;
esac

case "$fx_hits" in
  *hosted.yml*)
    echo "FAIL: fired on a hosted runner, where these commands are correct"
    exit 1 ;;
  *) echo "ok: hosted jobs are correctly out of scope" ;;
esac

# ---------------------------------------------------------------------------
# PART 2 - now run the proven instrument over the real tree.
# ---------------------------------------------------------------------------
out=$(run_census .) || { echo "FAIL: census did not run on the repo"; exit 1; }
censused=$(printf '%s\n' "$out" | head -1)
offenders=$(printf '%s\n' "$out" | tail -n +2 | sed '/^$/d')

if [ "${censused:-0}" -eq 0 ]; then
  echo "note: 0 self-hosted fleet jobs in this tree - the class cannot fire"
  echo "      here yet, and the fixtures above are what keeps this guard live"
  echo "      until the fleet migration lands."
else
  echo "ok: censused ${censused} self-hosted fleet jobs"
fi

if [ -n "$offenders" ]; then
  echo "FAIL: fleet job(s) install an executable to a path every slot shares:"
  printf '%s\n' "$offenders" | sed 's/^/  /'
  echo ""
  echo "Two of these running at once leave one job exec'ing a half-written"
  echo "binary: exit 126, on one slot only, with a clean log."
  echo ""
  echo "Install into \$RUNNER_TEMP, which is private per job on hosted and"
  echo "self-hosted runners alike, and put it on PATH:"
  echo ""
  echo "    mkdir -p \"\$RUNNER_TEMP/bin\""
  echo "    ... -b \"\$RUNNER_TEMP/bin\" <version>"
  echo "    echo \"\$RUNNER_TEMP/bin\" >> \"\$GITHUB_PATH\""
  echo ""
  echo "For npm use --prefix \"\$RUNNER_TEMP/<tool>\" and add"
  echo "<prefix>/node_modules/.bin to \$GITHUB_PATH - regression-test-required.yml"
  echo "installs spectral that way already."
  exit 1
fi

echo "PASS: no fleet job installs an executable to a path its siblings share"
