#!/usr/bin/env bash
# nightly_dispatch_never_publishes_test.sh
#
# A TEST SWEEP MUST NEVER BE ABLE TO PUBLISH.
#
# WHAT HAPPENED. `.github/scripts/nightly-e2e-dispatch.py` chooses the nightly
# post-merge suite set by a PROPERTY: "some `run:` step boots a stack". Until
# this guard, that property was a substring search over the whole `run:` body,
#
#     BOOTS = re.compile(r"docker[ -]compose|runtime-e2e/\S+\.(sh|py)")
#
# so a MENTION satisfied it. `.github/workflows/sync-community-repo.yml` - the
# community PUBLISH pipeline, which never runs compose - matched nine times:
# two prose comments, six `rsync --exclude='docker-compose.*.yml'` filename
# arguments, and one `docker-compose-test` job name passed as an argument. A
# `nightly-e2e.yml` dispatch with `all=true` therefore ran the publish pipeline
# twice on 2026-09-08 (runs 34237273184, 34250968298), opening the unwanted
# getaxonflow/axonflow#490 and #491.
#
# OPERATOR RULING, 2026-09-09: there is no automated community sync and there
# must not be one. The sync happens as part of the release train, or on demand
# when it makes sense. Nothing that runs on a schedule may publish.
#
# TWO INDEPENDENT DEFENCES, and this guard pins BOTH because either alone can
# be undone by an ordinary edit:
#
#   1. The classifier detects an INVOCATION, not a mention. The `run:` body is
#      reduced to the commands it would execute (whole-line comments dropped,
#      backslash continuations joined, split on shell separators, env-assignment
#      and keyword prefixes peeled) and the token must be the COMMAND WORD - or
#      the script handed to an interpreter. An `--exclude=` argument, an
#      argument to any other command, and a comment can no longer satisfy it.
#
#   2. A workflow that can WRITE OUTSIDE THIS REPOSITORY is refused whatever
#      the classifier says - a forge write verb, a publishing action, a
#      checkout of another repository, or a forge credential other than the
#      run-scoped GITHUB_TOKEN. Defence 1 is a heuristic over free-form shell;
#      the day a publish pipeline gains a real compose call, defence 1 stops
#      helping and only this refusal is left.
#
# Both directions are pinned. Over-matching is what shipped the incident;
# UNDER-matching silently shrinks the nightly set, which is the only routine
# coverage those 76 suites get, so the positive fixtures and the real-tree
# floor are assertions too.
#
# Run: bash tests/regression-test-required/nightly_dispatch_never_publishes_test.sh

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DISPATCHER="$REPO_ROOT/.github/scripts/nightly-e2e-dispatch.py"
SYNC_WORKFLOW="$REPO_ROOT/.github/workflows/sync-community-repo.yml"

PASS=0
FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

echo "=== the nightly dispatcher cannot dispatch a publish ==="

# The dispatcher IS mirrored to getaxonflow/axonflow (it is not in the sync
# workflow's exclude chain), so part 1 below runs there too. A missing
# dispatcher in an ENTERPRISE tree is a failure, never a skip.
if [ ! -f "$DISPATCHER" ]; then
  if [ -d "$REPO_ROOT/ee" ]; then
    bad "$DISPATCHER not found in an enterprise tree - this guard cannot vacuously pass"
    exit 1
  fi
  echo "  SKIP: no nightly dispatcher in this checkout"
  exit 0
fi
if ! python3 -c 'import yaml' 2>/dev/null; then
  bad "PyYAML is unavailable; a guard that cannot import the dispatcher must not report success"
  exit 1
fi

# ---------------------------------------------------------------------------
# THE PROBE. Loads the dispatcher AS A MODULE and drives its real functions
# over fixtures, so what is measured is the code that runs - not a
# re-implementation of it, which would agree with itself either way.
#
# Prints KEY=VALUE. Every list key is a list of FAILING fixture ids, so an
# empty value is the pass state and a probe that crashed prints nothing at all
# (which the bash rows below treat as a failure, not as an empty list).
# ---------------------------------------------------------------------------
probe() {
  local dispatcher="$1"
  python3 - "$dispatcher" "$REPO_ROOT" <<'PY'
import importlib.util, io, os, re, sys, tempfile, yaml

spec = importlib.util.spec_from_file_location("nd", sys.argv[1])
nd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nd)
repo_root = sys.argv[2]

# --- fixtures ------------------------------------------------------------
# MUST be classified as booting a stack. These are the shapes the real suites
# use; a classifier that stops matching them empties the nightly set.
POSITIVE = {
    "compose_v2":        "docker compose up -d",
    "compose_v1":        "docker-compose -f docker-compose.yml up -d",
    "compose_after_cd":  "cd runtime-e2e/3593 && docker compose up -d --wait",
    "compose_env_pfx":   "COMPOSE_PROJECT_NAME=wt1 docker compose up -d",
    "compose_abs_path":  "/usr/local/bin/docker-compose up -d",
    "compose_flag_first":"docker --log-level debug compose up -d",
    "suite_direct":      "./runtime-e2e/2926_rbac_e2e/test.sh",
    "suite_bash":        "bash runtime-e2e/2926_rbac_e2e/test.sh",
    "suite_python":      "python3 runtime-e2e/3604_durable_stores/check.py",
    "suite_if_prefix":   "if bash runtime-e2e/x/test.sh; then echo ok; fi",
}
# MUST NOT be classified as booting a stack. Every one of these is a line the
# ORIGINAL substring classifier accepted - they are quoted from, or shaped
# exactly like, `sync-community-repo.yml`.
NEGATIVE = {
    "rsync_exclude":     "rsync -a --exclude='docker-compose.test.yml' src/ dst/",
    "rsync_exclude_cont":(
        "rsync -a \\\n"
        "  --exclude='docker-compose.sessd.yml' \\\n"
        "  --exclude='docker-compose.scaled.yml' \\\n"
        "  src/ dst/"
    ),
    "comment_only":      "# NB: docker-compose.sessd.yml is a Session D artefact",
    "comment_suite":     "# 66 suites are migrated onto runtime-e2e/lib/wait_for_stack.sh",
    "job_name_argument": (
        "LOG_DIR=\"$RUNNER_TEMP/x\" \\\n"
        "  scripts/ci/run-community-job-in-mirror.sh \"$RUNNER_TEMP/m\" \\\n"
        "    docker-compose-test"
    ),
    "similar_command":   "docker-compose-test --dry-run",
    "echo_mention":      "echo \"see runtime-e2e/2926_rbac_e2e/test.sh for the shape\"",
    "grep_mention":      "grep -rn 'docker compose' .github/workflows/",
}

print("POS_FAIL=" + ",".join(sorted(k for k, v in POSITIVE.items()
                                    if not nd.invokes_stack_boot(v))))
print("NEG_FAIL=" + ",".join(sorted(k for k, v in NEGATIVE.items()
                                    if nd.invokes_stack_boot(v))))

# --- defence 2, on a workflow that ALSO boots a stack ---------------------
# This is the fixture that ONLY defence 2 can refuse: it really does invoke
# compose, so defence 1 correctly says "boots a stack". If the refusal is ever
# removed, this row - and only this row - goes red.
PUBLISHER = yaml.safe_load("""
name: Publish and boot
on:
  workflow_dispatch:
  schedule: [{cron: '0 3 * * *'}]
jobs:
  go:
    runs-on: ubuntu-latest
    steps:
      - run: docker compose up -d
      - run: |
          git push origin HEAD:refs/heads/sync
""")
SUITE = yaml.safe_load("""
name: Ordinary suite
on:
  workflow_dispatch:
  push:
    tags: [v*]
jobs:
  go:
    runs-on: ubuntu-latest
    steps:
      - run: docker compose up -d
""")
CHECKOUT_ELSEWHERE = yaml.safe_load("""
name: Checks out another repo
on:
  workflow_dispatch:
jobs:
  go:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          repository: getaxonflow/axonflow
      - run: docker compose up -d
""")
CREDENTIAL = """
name: Uses a sync credential
on:
  workflow_dispatch:
jobs:
  go:
    runs-on: ubuntu-latest
    steps:
      - run: docker compose up -d
        env:
          GH_TOKEN: ${{ secrets.GH_SYNC_TOKEN }}
"""

print("PUBLISHER_BOOTS=%d" % int(nd.boots_a_stack(PUBLISHER)))
print("PUBLISHER_IN_SET=%d" % int(nd.in_nightly_set(PUBLISHER, "")))
print("SUITE_IN_SET=%d" % int(nd.in_nightly_set(SUITE, "")))
print("CHECKOUT_IN_SET=%d" % int(nd.in_nightly_set(CHECKOUT_ELSEWHERE, "")))
print("CRED_IN_SET=%d" % int(nd.in_nightly_set(yaml.safe_load(CREDENTIAL), CREDENTIAL)))
# The run-scoped GITHUB_TOKEN is not a cross-repo credential and must not
# refuse an ordinary suite.
DEFAULT_TOK = CREDENTIAL.replace("secrets.GH_SYNC_TOKEN", "secrets.GITHUB_TOKEN")
print("DEFAULT_TOKEN_IN_SET=%d" % int(nd.in_nightly_set(yaml.safe_load(DEFAULT_TOK), DEFAULT_TOK)))

# --- the real sync workflow, when this tree has one ------------------------
sync = os.path.join(repo_root, ".github", "workflows", "sync-community-repo.yml")
if os.path.exists(sync):
    raw = io.open(sync, encoding="utf-8").read()
    doc = yaml.safe_load(raw)
    # Anti-vacuity for the whole fixture class: the mention lines that caused
    # the incident must still BE there. If they are ever deleted, this guard
    # would start passing because the subject changed, not because the
    # classifier is right - and it says so instead.
    old = re.compile(r"docker[ -]compose|runtime-e2e/\S+\.(sh|py)")
    mentions = 0
    for job in (doc.get("jobs") or {}).values():
        for step in ((job or {}).get("steps") or []):
            mentions += len(old.findall(str((step or {}).get("run", "") or "")))
    print("SYNC_MENTIONS=%d" % mentions)
    print("SYNC_BOOTS=%d" % int(nd.boots_a_stack(doc)))
    print("SYNC_WRITES=%s" % (nd.writes_outside_this_repo(doc, raw) or ""))
    print("SYNC_IN_SET=%d" % int(nd.in_nightly_set(doc, raw)))
PY
}

OUT="$(probe "$DISPATCHER")"
if [ -z "$OUT" ]; then
  bad "the probe produced no output - the dispatcher could not be imported or driven"
  echo ""; echo "FAILED: $FAIL check(s)"; exit 1
fi
get() { printf '%s\n' "$OUT" | sed -n "s/^$1=//p" | head -1; }

# ---------------------------------------------------------------------------
# 1. The classifier: invocation, not mention. Runs in every tree.
# ---------------------------------------------------------------------------
[ -z "$(get POS_FAIL)" ] &&
  ok "every real invocation shape is still classified as booting a stack" ||
  bad "invocations no longer detected: $(get POS_FAIL) - the nightly set shrinks silently"

[ -z "$(get NEG_FAIL)" ] &&
  ok "no comment, --exclude= filename or other argument can satisfy the classifier" ||
  bad "MENTIONS accepted as invocations: $(get NEG_FAIL) - the classifier has regressed to substring matching"

# ---------------------------------------------------------------------------
# 2. Defence 2, independent of the classifier.
# ---------------------------------------------------------------------------
[ "$(get SUITE_IN_SET)" = "1" ] &&
  ok "control: an ordinary dispatchable compose suite IS in the nightly set" ||
  bad "an ordinary compose suite is not in the nightly set; the rows below would pass vacuously"

[ "$(get DEFAULT_TOKEN_IN_SET)" = "1" ] &&
  ok "control: the run-scoped GITHUB_TOKEN does not refuse a suite" ||
  bad "a suite using the run-scoped GITHUB_TOKEN was refused; the refusal is over-broad"

[ "$(get PUBLISHER_BOOTS)" = "1" ] &&
  ok "control: the publisher fixture genuinely boots a stack, so only defence 2 can refuse it" ||
  bad "the publisher fixture does not boot a stack; it no longer isolates defence 2"

[ "$(get PUBLISHER_IN_SET)" = "0" ] &&
  ok "a workflow that boots a stack AND pushes to a repo is refused" ||
  bad "a workflow that runs 'git push' is in the nightly set - a test sweep can publish"

[ "$(get CHECKOUT_IN_SET)" = "0" ] &&
  ok "a workflow that checks out another repository is refused" ||
  bad "a workflow checking out another repository is in the nightly set"

[ "$(get CRED_IN_SET)" = "0" ] &&
  ok "a workflow carrying a non-default forge credential is refused" ||
  bad "a workflow using secrets.GH_SYNC_TOKEN is in the nightly set"

# ---------------------------------------------------------------------------
# 3. The real sync workflow. Stripped from the community mirror, so absent
#    there; absent in an ENTERPRISE tree is a failure, never a skip.
# ---------------------------------------------------------------------------
if [ ! -f "$SYNC_WORKFLOW" ]; then
  if [ -d "$REPO_ROOT/ee" ]; then
    bad "$SYNC_WORKFLOW not found in an enterprise tree - the real-tree rows cannot vacuously pass"
  else
    echo "  SKIP: community checkout (sync-community-repo.yml is stripped from the mirror); parts 1-2 ran"
  fi
else
  m="$(get SYNC_MENTIONS)"
  [ "${m:-0}" -ge 5 ] &&
    ok "sync-community-repo.yml still carries $m substring mentions, so this is a live subject" ||
    bad "sync-community-repo.yml carries only ${m:-0} mention(s); the guard would pass because the subject changed"

  [ "$(get SYNC_BOOTS)" = "0" ] &&
    ok "defence 1: the sync pipeline is not classified as booting a stack" ||
    bad "defence 1: the sync pipeline is STILL classified as booting a stack"

  [ -n "$(get SYNC_WRITES)" ] &&
    ok "defence 2: the sync pipeline is refused independently ($(get SYNC_WRITES))" ||
    bad "defence 2: nothing about the sync pipeline reads as writing outside this repository"

  [ "$(get SYNC_IN_SET)" = "0" ] &&
    ok "sync-community-repo.yml is not in the nightly set" ||
    bad "sync-community-repo.yml IS in the nightly set - a nightly sweep would publish"

  # And end to end, through the script's own entry point: the dispatch table
  # must not name it, and the refusal list must.
  DRY="$(cd "$REPO_ROOT" && python3 "$DISPATCHER" --dry-run --all 2>/dev/null)"
  rc=$?
  if [ $rc -ne 0 ]; then
    bad "the dispatcher exited $rc on --dry-run --all against the real tree"
  else
    if printf '%s\n' "$DRY" | grep -q '^| `sync-community-repo.yml`'; then
      bad "--dry-run --all lists sync-community-repo.yml in the dispatch table"
    else
      ok "--dry-run --all does not dispatch sync-community-repo.yml"
    fi
    n="$(printf '%s\n' "$DRY" | sed -n 's/.*stack-booting workflows: \*\*\([0-9]*\)\*\*.*/\1/p')"
    [ "${n:-0}" -ge 60 ] &&
      ok "the nightly set still holds $n suites (floor 60) - the fix did not shrink coverage" ||
      bad "the nightly set holds only ${n:-0} suites; the classifier is now under-matching"
    r="$(printf '%s\n' "$DRY" | sed -n 's/.*refused as publish\/sync workflows[^*]*\*\*\([0-9]*\)\*\*.*/\1/p')"
    [ "${r:-0}" -ge 1 ] &&
      ok "the run reports $r refused publish/sync workflow(s), so the refusal is observable" ||
      bad "the run reports no refused publish/sync workflows; a defence nothing prints cannot be audited"
    printf '%s\n' "$DRY" | grep -q 'sync-community-repo.yml.*forge' &&
      ok "the refusal block names sync-community-repo.yml and why" ||
      bad "the refusal block does not name sync-community-repo.yml"
  fi
fi

# ---------------------------------------------------------------------------
# 4. THE GUARD'S OWN FALSIFIABILITY.
#
# Every row above claims something is true of the dispatcher. A probe that had
# stopped exercising the dispatcher would report them all true as well, so each
# defence is re-measured against a COPY of the dispatcher broken in exactly
# that dimension, and this guard fails if the break is not detected.
#
# Three ways a mutation lies, all checked here:
#   * the plant never landed  -> the anchor must be present, or the row fails;
#   * the plant broke the file -> every mutant is PARSE-CHECKED before its
#     result is believed, because a syntax error reds everything and reads
#     exactly like "detected";
#   * the exit code measured was the pipe's -> the probe's output is captured
#     into a variable and the KEY read from it, never `grep | ...; $?`.
# ---------------------------------------------------------------------------
echo ""
echo "=== the guard's own falsifiability ==="

TMP="$(mktemp -d "${TMPDIR:-/tmp}/nightly-publish-guard.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

mutant() {  # $1 name, $2 old, $3 new, $4 key, $5 want-value-of-key
  local name="$1" old="$2" new="$3" key="$4" want="$5"
  local f="$TMP/mutant.py"
  python3 - "$DISPATCHER" "$f" "$old" "$new" <<'PY'
import io, sys
src, dst, old, new = sys.argv[1:5]
text = io.open(src, encoding='utf-8').read()
if text.count(old) != 1:
    sys.stderr.write('anchor appears %d times, want exactly 1: %r\n' % (text.count(old), old))
    raise SystemExit(3)
io.open(dst, 'w', encoding='utf-8').write(text.replace(old, new, 1))
PY
  if [ $? -ne 0 ]; then
    bad "mutant '$name' could not be built; its anchor is no longer in the dispatcher"
    return
  fi
  if ! python3 -c 'import ast,io,sys; ast.parse(io.open(sys.argv[1]).read())' "$f" 2>/dev/null; then
    bad "mutant '$name' does not parse - VOID: a syntax error reds every row and proves nothing"
    return
  fi
  local out got
  out="$(probe "$f")"
  got="$(printf '%s\n' "$out" | sed -n "s/^$key=//p" | head -1)"
  if [ -z "$out" ]; then
    bad "mutant '$name' produced no probe output - VOID, not a kill"
  elif [ "$got" = "$want" ]; then
    ok "mutant '$name' killed: the probe reports $key=$got"
  else
    bad "mutant '$name' SURVIVED: probe reports $key=${got:-<empty>}, want $want"
  fi
}

# M1 - the classifier reverted to the pre-fix substring search. Every mention
# fixture must be reported as accepted.
mutant "classifier back to substring matching" \
  '    for cmd, args in _commands(run):
        base = cmd.rsplit("/", 1)[-1]' \
  '    if re.search(r"docker[ -]compose|runtime-e2e/\S+\.(sh|py)", run):
        return True
    for cmd, args in _commands(run):
        base = cmd.rsplit("/", 1)[-1]' \
  NEG_FAIL "comment_only,comment_suite,echo_mention,grep_mention,job_name_argument,rsync_exclude,rsync_exclude_cont,similar_command"

# M2 - the command word matched as a PREFIX instead of exactly. A neighbouring
# command name (`docker-compose-test`) then counts as compose.
mutant "command word matched loosely" \
  '        if base == "docker-compose":' \
  '        if base.startswith("docker-compose"):' \
  NEG_FAIL "similar_command"

# M3 - separator splitting removed. Under-matching, the other failure
# direction: a compose call after `cd x &&` stops being seen.
mutant "shell separators no longer split commands" \
  '        for segment in _SEPARATORS.split(line):' \
  '        for segment in [line]:' \
  POS_FAIL "compose_after_cd,suite_if_prefix"

# M4 - defence 2 deleted. Defence 1 still (correctly) says the publisher boots
# a stack, so this row is the only thing standing between a sweep and a push.
mutant "publish refusal removed from in_nightly_set" \
  '    if writes_outside_this_repo(doc, raw):
        return False          # a test sweep must never be able to publish
' \
  '' \
  PUBLISHER_IN_SET 1

# M5 - the push verb dropped from the forge-write set.
#
# ANCHORED ON THE POSITIONAL TEST, NOT THE REGEX. The verb used to be matched by
# searching `_FORGE_WRITE` over the rejoined command line; it is now read
# positionally in `_forge_write_verb`, because rejoining re-created the
# mention-matching defect defence 1 exists to remove (`echo "  git push"` was
# refusing commit-lint.yml). This mutant was left pointing at the old regex and
# SURVIVED - it was editing a pattern nothing consults any more, which is the
# plant-never-landed failure. The guard caught it; the anchor is corrected here.
mutant "git push no longer counts as a forge write" \
  '        if a[:1] == ["push"]:' \
  '        if a[:1] == ["shove"]:' \
  PUBLISHER_IN_SET 1

if [ "$FAIL" -gt 0 ]; then
  echo ""
  echo "FAILED: $FAIL check(s), $PASS passed"
  exit 1
fi
echo ""
echo "PASS: $PASS check(s) - the nightly dispatcher classifies invocations, refuses publishers, and both defences are falsifiable"
