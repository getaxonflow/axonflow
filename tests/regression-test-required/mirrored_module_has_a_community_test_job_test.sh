#!/usr/bin/env bash
# mirrored_module_has_a_community_test_job_test.sh - #3574
#
# A Go module that MIRRORS to the public community repository but whose only
# test workflow does NOT mirror is a module whose entire test suite lands there
# as files that never execute.
#
# That is exactly what happened to platform/decision. The community sync is
# exclude-based: it excludes `.github/workflows/test.yml` by name and excludes
# nothing under `platform/decision`, so on getaxonflow/axonflow the module is
# present and the workflow that runs it is not. Nothing goes red. The
# conformance corpus, the disposition-ledger guard, the tri-state corpus, the
# mutation proofs, the round-trip property and the authoring gates are simply
# absent from the lane that gates an outside contributor's pull request.
#
# It is a silent-mirror defect of the same class as the //go:build strip, and
# the reason it needs a ratchet rather than a fix is that nothing about adding a
# second module would remind anyone: `go test ./...` from platform/ does not
# descend into a separate module, so a new module is invisible to every existing
# job by construction.
#
# THE RULE: every Go module under platform/ that reaches the community mirror
# must be run by a job in a workflow that ALSO reaches the mirror, and that job
# must gate the mirror's own summary check.
#
# EXTENDED (#3574, second pass). Two more findings of the same class:
#
#   - The ROOT platform module was "covered" by three per-service steps that
#     `cd` into orchestrator/, agent/ and connectors/, and only the last says
#     `./...`. Every other package in that module - all of platform/shared/*
#     including the ADR-065 identity plane, every orchestrator and agent
#     subpackage - ran in NO job in the untagged build. Module discovery cannot
#     see inside a module, so the root module now needs its own lane, and this
#     test asserts that lane exists in the mirrored workflow, selects packages
#     by `go list ./...` rather than by name, and carries its identity canary.
#
#   - "Gates the summary" was checked against `needs:` alone. A job in `needs`
#     that the summary's failure expression never reads is a job whose red
#     stops nothing. Both halves are now asserted: needs AND
#     `needs.<job>.result` in the failure step's `if:`.
#
# EXTENDED (#3728). Both assertions matched a lane by the LITERAL `cd <module>`
# its steps perform. That is correct for a lane that names its modules and
# wrong the moment one derives them: the standalone-modules lane now discovers
# every go.mod under platform/ and scripts/ and runs `cd "$m"` in a loop, and
# against the old text this test read as "no job runs platform/cmd/axonctl"
# while the summary-gating half went vacuous for that same job. So a module
# counts as executed if a lane names it OR a lane derives it and does not
# exempt it, and a job counts as running platform code under either spelling.
# The derived branch carries two-sided controls: it must accept a module the
# lane discovers and refuse one the lane exempts.
#
# EXTENDED (#3728 round 3). The round-2 matchers above were reviewed by attack
# and four defects were reproduced. All four are in the guard, not the workflow,
# and three of the four red a CORRECT tree - the direction that matters here,
# because this file gates the required regression suite and therefore the
# required `Test Summary`: a miss is silent, a false positive reds correct work
# and teaches everyone the guard is noise.
#
#   - The exemption test was `module in exempt_line` - a SUBSTRING match, where
#     the lane it models uses `grep -qxF`, an EXACT one. A real module
#     `platform/dec` that the lane does select was reported unrun. The mirror
#     image is the silent direction: an EXEMPT entry naming `platform/decisionX`
#     made a query for `platform/decision` read as exempt, i.e. a module the
#     lane genuinely skips scored as covered - the #3574 defect itself.
#   - The round-2 clause in the summary-wiring half ran on RAW `run:` text, so a
#     job mentioning `cd "$m"` and `go test ./...` inside `#` comments was
#     scored as running platform code. Both halves of that predicate now go
#     through `code_lines()`, which is the class fix rather than the instance.
#   - Both matchers were keyed on the LITERAL loop-variable spelling `cd "$m"`.
#     A behaviour-identical rename to `mod` in both workflows re-vacuated the
#     wiring half for the changed job AND emitted two false module findings.
#     The loop variable is now free.
#   - "A guard that cannot run must not pass" was enforced by an `exit 1` inside
#     a `$( )`, which exits the substitution and not the script. The interpreter
#     is now probed ONCE at the top level, before any assertion, and the two
#     causes it can actually observe are reported separately.
#
# And the fixes are PINNED, which the round-2 fixes were not: deleting the
# round-2 clause outright left this guard green at 8/8. The FIXTURES section
# below drives the real matchers against synthetic workflows, in both
# directions, including one built from the real lane's own step text.
#
# Run: bash tests/regression-test-required/mirrored_module_has_a_community_test_job_test.sh

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SYNC_WORKFLOW="$REPO_ROOT/.github/workflows/sync-community-repo.yml"
COMMUNITY_WORKFLOW="$REPO_ROOT/.github/workflows/test-community.yml"

PASS=0
FAIL=0
ok() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

echo "=== every mirrored platform module must be executed by the mirrored test workflow ==="

if [ ! -f "$COMMUNITY_WORKFLOW" ]; then
  echo "  FAIL: $COMMUNITY_WORKFLOW not found - this test cannot vacuously pass"
  exit 1
fi

# The sync workflow is EXCLUDED from the mirror, so on a mirror checkout it is
# absent. The exclusion analysis below is therefore enterprise-only; the
# execution assertions that follow run in both trees, which is the half that
# matters on the mirror.
HAVE_SYNC=1
[ -f "$SYNC_WORKFLOW" ] || HAVE_SYNC=0

# EVERY ASSERTION BELOW PARSES YAML, so the interpreter is probed ONCE, here, at
# the TOP LEVEL - before the module loop and before any control.
#
# The round-2 version enforced "a guard that cannot run must not pass" with an
# `exit 1` inside the helper, and the helper is called as
# `LANE="$(derived_lane_covering ...)"`. A command substitution is a subshell:
# that `exit 1` ended the substitution and the loop carried on, so with PyYAML
# unimportable the guard printed the exact false finding about test-community.yml
# that the comment claimed it prevented ("platform/cmd/axonctl mirrors ... and
# no job runs it"). Measured, #3728 round 3.
#
# The two causes below are the two this script can actually OBSERVE. It does not
# guess at which import failed inside a subprocess whose rc it cannot attribute.
PROBE_CAUSE=""
if ! command -v python3 >/dev/null 2>&1; then
  PROBE_CAUSE="python3 is not on PATH"
elif ! python3 -c 'import yaml' >/dev/null 2>&1; then
  PROBE_CAUSE="python3 is present but \`python3 -c 'import yaml'\` failed, so PyYAML is unavailable"
fi
if [ -n "$PROBE_CAUSE" ]; then
  echo "  FAIL: $PROBE_CAUSE"
  echo "        Every assertion in this guard parses a workflow with PyYAML, so none of them can run."
  echo "        A guard that cannot run must not pass. GitHub runners carry both, so this means the"
  echo "        environment changed and the assertions stopped running - a fact someone must see."
  echo ""
  echo "  passed: 0   failed: 1"
  exit 1
fi

# Discover the separate Go modules under platform/ rather than listing them.
# A listed module is a module somebody has to remember to add, and the whole
# defect this test exists for is that nobody was reminded.
#
# Exclusions, each deliberate (#3728 round 3): node_modules/ is vendored
# JavaScript; testdata/ is ignored by the Go toolchain BY CONSTRUCTION and
# platform/ already holds three such trees, so a fixture module there would make
# this guard demand a community job for a module no lane should run; vendor/ is
# a copy of somebody else's module. Nothing else is excluded on purpose - a real
# module anywhere else under platform/ must be discovered.
MODULES="$(find "$REPO_ROOT/platform" -name go.mod \
  -not -path '*/node_modules/*' \
  -not -path '*/testdata/*' \
  -not -path '*/vendor/*' \
  -print0 |
  xargs -0 -n1 dirname |
  sed "s|^$REPO_ROOT/||" |
  sort)"

if [ -z "$MODULES" ]; then
  echo "  FAIL: no Go modules were found under platform/ - the discovery has stopped working"
  exit 1
fi
ok "discovered $(echo "$MODULES" | wc -l | tr -d ' ') Go module(s) under platform/ (anti-vacuity check)"

# ---------------------------------------------------------------------------
# SHARED PYTHON PRELUDE
#
# Both halves of this guard match the same three things in workflow scripts, so
# they share ONE spelling of each rule. Round 2 had two copies of the
# comment-stripping idea - a named helper in the wiring half and an inline
# expression in the derived half - and the clause added in round 2 called
# neither, which is how a marker ended up matching prose. A rule the callers
# share belongs one frame down, not copied at each call site.
# ---------------------------------------------------------------------------
PY_PRELUDE="$(
  cat <<'PYP'
import os
import re
import sys

# The caller probes python3 and PyYAML at the top level before any assertion
# runs, so reaching this line with PyYAML missing means the environment changed
# under a running script. It still must not be reported as a finding about the
# workflow: an UNCAUGHT ImportError here exits 1, and exit 1 is this program's
# spelling of "no job runs this module". Measured (#3728 round 3): with the
# top-level probe removed and PyYAML unimportable, an uncaught import here made
# the guard publish "platform/cmd/axonctl mirrors ... and no job runs it" -
# exactly the false finding the probe exists to prevent. Rc 3 makes the caller
# abort as a broken instrument, so the property does not rest on the probe alone.
try:
    import yaml
except Exception as exc:  # noqa: BLE001 - deliberately broad; see above
    print("PyYAML is unavailable (%r)" % (exc,), file=sys.stderr)
    sys.exit(3)


def code_lines(script):
    """The script with `#` comment lines removed.

    Every marker match in this file goes through here. A marker that matches the
    prose BESIDE a check survives the deletion of the check it stands for, and
    this repository comments its workflow steps heavily enough that the two are
    routinely one grep apart. Reproduced in #3728 round 3: a job whose only run
    step mentioned `cd "$m"` and `go test ./...` inside two comment lines was
    scored as running platform code and reported as ungated.
    """
    return "\n".join(
        l for l in str(script or "").splitlines() if not l.strip().startswith("#")
    )


# `cd "<var>"` with the LOOP VARIABLE LEFT FREE. Round 2 matched the literal
# `cd "$m"`; renaming that variable to `mod` in both workflows - a
# behaviour-identical edit that preserves twin parity - re-vacuated the wiring
# half for the very job #3728 had just changed, while emitting two false module
# findings. A guard keyed on an arbitrary identifier is a guard one rename from
# vacuous.
CD_LOOP_VAR = re.compile(r'cd\s+"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?"')

# The lane's own exemption mechanism, mirrored EXACTLY:
#
#   EXEMPT='<module> :: <reason>'          (one entry per line)
#   EXEMPT_PATHS="$(printf '%s\n' "$EXEMPT" | sed 's/ :: .*//')"
#   ... | grep -qxF "$m"
#
# `grep -qxF` is a WHOLE-LINE, FIXED-STRING match. Round 2 modelled it with
# `module in exempt_line`, a substring test, and that is wrong in both
# directions: `platform/dec` (a module the lane selects) read as exempt because
# it is a substring of the `platform/decision` entry, and an entry naming
# `platform/decisionX` would make a query for `platform/decision` read as exempt
# - scoring a module the lane genuinely skips as covered, which is the #3574
# defect this file exists to catch.
EXEMPT_ASSIGN = re.compile(r"^[ \t]*EXEMPT[A-Za-z0-9_]*=(['\"])(.*?)\1", re.M | re.S)


def exempt_paths(code):
    """The exact module paths the lane's EXEMPT assignments name."""
    out = []
    for _quote, value in EXEMPT_ASSIGN.findall(code):
        for entry in value.splitlines():
            entry = entry.split(" :: ", 1)[0].strip()
            if entry:
                out.append(entry)
    return out
PYP
)"

# derived_lane_covering <module> [workflow] - print the id of a job that tests
# <module> by DERIVATION and exit 0; exit 1 when no job does; exit >= 2 when the
# check itself could not run.
#
# A job qualifies only if one of its run steps does all three: discovers
# `go.mod` files with a `find` whose path list includes the module's top-level
# prefix, tests each discovery with `go test ./...` from inside it
# (`cd "<var>"`), and does NOT name the module on an EXEMPT line.
#
# THE EXIT STATUS IS THE INTERFACE, and it is the caller's job to act on it. The
# round-2 version tried to `exit 1` from inside here; it is called in a `$( )`,
# so that exited the substitution and the caller carried on printing findings
# about the workflow. The interpreter is probed at the top level instead, and an
# rc >= 2 here means something ELSE broke (a rc of 127 for a python3 that
# vanished mid-run, a scanner error on a malformed workflow) - which the caller
# reports as a broken instrument rather than as a fact about the workflow.
PY_DERIVED="$(
  cat <<'PYD'
def main(wf, module):
    prefix = module.split("/")[0]
    with open(wf) as fh:
        doc = yaml.safe_load(fh)

    find_re = re.compile(
        r"find\b[^\n|]*\b%s\b[^\n|]*-name\s+go\.mod" % re.escape(prefix)
    )

    for name, job in (doc.get("jobs") or {}).items():
        for step in (job.get("steps") or []):
            code = code_lines(step.get("run"))
            if not find_re.search(code):
                continue
            if not CD_LOOP_VAR.search(code) or "go test ./..." not in code:
                continue
            if module in exempt_paths(code):
                continue
            print(name)
            return 0
    return 1


# Rc 3, not 1, for anything unexpected. A workflow the YAML scanner rejects
# raises here, and an uncaught raise exits 1 - which the caller would read as
# "no job runs this module", i.e. a real finding about the workflow. A scanner
# error is a broken instrument and must be reported as one (#3728 round 3).
try:
    RC = main(sys.argv[1], sys.argv[2])
except Exception as exc:  # noqa: BLE001 - deliberately broad; see above
    print("the derived-lane check raised %r" % (exc,), file=sys.stderr)
    RC = 3
sys.exit(RC)
PYD
)"

derived_lane_covering() {
  local module="$1"
  local wf="${2:-$COMMUNITY_WORKFLOW}"
  printf '%s\n%s\n' "$PY_PRELUDE" "$PY_DERIVED" | python3 - "$wf" "$module"
}

# The root platform module is run by `unit-tests` in the community workflow
# under its own per-service steps, which predate this rule and are asserted by
# other gates. This test is about the modules that `go test ./...` from
# platform/ cannot reach.
for MODULE in $MODULES; do
  [ "$MODULE" = "platform" ] && continue

  if [ "$HAVE_SYNC" -eq 1 ]; then
    # Does this module reach the mirror at all? An excluded module needs no
    # community job, and asserting one for it would be wrong rather than
    # merely noisy.
    if grep -qF -- "--exclude='$MODULE/'" "$SYNC_WORKFLOW"; then
      ok "$MODULE is excluded from the community sync, so it needs no community test job"
      continue
    fi
  fi

  # The community workflow must actually run this module. Matching on what the
  # steps DO, rather than on a job name, because a job name is a label.
  #
  # Two shapes count, and the second was added in #3728. A lane may name the
  # module (`cd <module>`), or it may DERIVE its members - discover the go.mod
  # files under a prefix and test each one. The derived shape has to count,
  # because this test's own discovery loop exists on the premise that a listed
  # module is one somebody has to remember to add; a lane that stopped listing
  # is the fix, and rejecting it would pin the defect in place. What is not
  # allowed is a lane that derives and then exempts THIS module: an exempted
  # module is deliberately outside the derivation and still needs its own `cd`.
  if grep -qE "^[[:space:]]+cd $MODULE\$" "$COMMUNITY_WORKFLOW"; then
    ok "$MODULE is executed by name in $(basename "$COMMUNITY_WORKFLOW")"
    continue
  fi

  # `LANE="$( ... )"; rc=$?` - the status after an assignment whose value comes
  # from a command substitution IS the substitution's status. The three cases
  # are kept apart on purpose: "not covered" is a finding about the workflow,
  # while "the check broke" is a finding about the instrument, and round 2
  # printed the first when it meant the second.
  LANE="$(derived_lane_covering "$MODULE")"
  rc=$?
  case "$rc" in
    0)
      ok "$MODULE is executed by derivation in $(basename "$COMMUNITY_WORKFLOW") (job $LANE)"
      ;;
    1)
      bad "$MODULE mirrors to the community repository and no job in $(basename "$COMMUNITY_WORKFLOW") runs it;"
      echo "        neither by a \`cd $MODULE\` step nor by a lane that derives its members from go.mod discovery."
      echo "        Its whole test suite would land on the public repo and never execute (#3574)."
      ;;
    *)
      # ANY rc >= 2, not just 2: a vanished python3 exits 127 and a workflow the
      # scanner chokes on exits 1 from the traceback path, and round 2's
      # `rc -eq 2` special case saw neither. This `exit` is at the top level of
      # the script, so it actually exits.
      echo "  FAIL: the derived-lane check exited $rc while examining $MODULE, so it did not run."
      echo "        A guard that cannot run must not pass, and this is NOT a finding about $(basename "$COMMUNITY_WORKFLOW")."
      echo ""
      echo "  passed: $PASS   failed: $((FAIL + 1))"
      exit 1
      ;;
  esac
done

# derived_says <expected-rc> <module> [workflow] - run the helper and compare.
# Written once so no control can accidentally read rc 127 as "not covered",
# which is how round 2's controls would have scored a vanished interpreter.
derived_says() {
  local want="$1"
  shift
  derived_lane_covering "$@" >/dev/null
  local got=$?
  if [ "$got" -ge 2 ]; then
    echo "  FAIL: the derived-lane check exited $got in a control; the instrument is broken, not the workflow"
    echo ""
    echo "  passed: $PASS   failed: $((FAIL + 1))"
    exit 1
  fi
  [ "$got" -eq "$want" ]
}

# Anti-vacuity for the derived branch, in BOTH directions, because a helper
# that always says yes and a helper that always says no are equally useless
# and both would leave the loop above reporting something. The two inputs are
# facts about this tree, not fixtures: platform/cmd/axonctl IS derived by the
# standalone-modules lane, and platform/decision is NAMED on that lane's
# EXEMPT line, so the helper must refuse it and the module must be carried by
# its own `cd` (which the loop above just asserted).
if derived_says 0 platform/cmd/axonctl; then
  ok "control: the derivation helper recognises a module the standalone lane discovers"
else
  bad "control: the derivation helper recognises nothing; the derived branch above cannot have been exercised"
fi
if derived_says 0 platform/decision; then
  bad "control: the derivation helper accepted platform/decision, which the standalone lane EXEMPTS; an exempted module would be scored as covered by a lane that skips it"
else
  ok "control: the derivation helper refuses a module the discovering lane exempts"
fi

# ---------------------------------------------------------------------------
# FIXTURES (#3728 round 3)
#
# The two controls above are facts about THIS tree, which is what makes them
# credible and also what makes them unable to vary the one axis under review: a
# control that reads the real workflow cannot ask "what would this matcher say
# if the exempt entry were spelled differently", and the two exemption defects
# are exactly that question. Deleting round 2's clause outright left this guard
# green at 8/8, so the fixes below are held by fixtures that fail when the fix
# is removed - a behaviour change without one is a demonstration, not a pin.
#
# The fixtures are synthetic workflows in a temp dir, driven through the SAME
# matchers the real assertions use. One of them is built from the real lane's
# own step text, so a future edit to the lane that the matcher cannot see reds
# this guard instead of silently going vacuous.
# ---------------------------------------------------------------------------
FIXDIR="$(mktemp -d)"
trap 'rm -rf "$FIXDIR"' EXIT

# write_derived_fixture <outfile> <exempt-path> <loop-var>
write_derived_fixture() {
  cat >"$1" <<'YAML'
name: derived-lane fixture
on: [push]
jobs:
  fixture-lane:
    steps:
      - name: Test every standalone Go module under platform/ and scripts/
        run: |
          EXEMPT='@EXEMPT@ :: a reason the matcher must not read'
          FOUND="$(find platform scripts -name go.mod -print0 | xargs -0 -n1 dirname | sort)"
          for @VAR@ in $FOUND; do
            (cd "$@VAR@" && go test ./... -count=1)
          done
YAML
  sed -i.bak -e "s|@EXEMPT@|$2|g" -e "s|@VAR@|$3|g" "$1"
  rm -f "$1.bak"
}

write_derived_fixture "$FIXDIR/exempt-decision.yml" platform/decision m
write_derived_fixture "$FIXDIR/exempt-decisionx.yml" platform/decisionX m
write_derived_fixture "$FIXDIR/renamed-loop-var.yml" platform/decision mod

# Direction 1 - THE FALSE POSITIVE that was reproduced. `platform/dec` is a
# module the lane selects and a substring of the `platform/decision` exempt
# entry. Under `module in line` it read as exempt, so the loop above reported
# "no job runs platform/dec" and the required regression suite went red on a
# correct workflow.
if derived_says 0 platform/dec "$FIXDIR/exempt-decision.yml"; then
  ok "fixture: a module whose path is a PREFIX of an exempt entry is not exempt (platform/dec vs platform/decision)"
else
  bad "fixture: platform/dec was treated as exempt because it is a substring of the platform/decision entry; the lane uses \`grep -qxF\` and selects it, so a correct workflow would be reported unrun"
fi

# Direction 2 - THE SILENT MISS, which is the worse half. An exempt entry naming
# platform/decisionX must NOT excuse platform/decision. Under `module in line`
# it did, and a module the lane genuinely skips would be scored as covered -
# the #3574 defect itself, reintroduced by its own guard.
if derived_says 0 platform/decision "$FIXDIR/exempt-decisionx.yml"; then
  ok "fixture: an exempt entry that merely CONTAINS a module path does not exempt it (platform/decisionX vs platform/decision)"
else
  bad "fixture: platform/decision was treated as exempt by an entry naming platform/decisionX; a module the lane skips would be scored covered (#3574)"
fi

# Direction 3 - and exactness must still REFUSE the exact entry. Without this,
# a matcher that exempted nothing at all would satisfy directions 1 and 2.
if derived_says 1 platform/decision "$FIXDIR/exempt-decision.yml"; then
  ok "fixture: the exact exempt entry is still refused, so the two fixtures above are not passing on a matcher that exempts nothing"
else
  bad "fixture: platform/decision was NOT refused by an EXEMPT entry naming it exactly; the exemption test has stopped working in the accepting direction"
fi

# Direction 4 - the loop variable is not part of the contract. Renaming `m` to
# `mod` in both workflows is behaviour-identical and preserves twin parity; it
# re-vacuated round 2's matcher.
if derived_says 0 platform/cmd/axonctl "$FIXDIR/renamed-loop-var.yml"; then
  ok "fixture: a lane that spells its loop variable \`mod\` instead of \`m\` is still recognised"
else
  bad "fixture: renaming the lane's loop variable defeated the derivation matcher; a behaviour-identical rename must not make this guard vacuous"
fi

# Direction 5 - a document the YAML scanner rejects must read as a BROKEN
# INSTRUMENT, not as "no job runs this module". Both are one non-zero exit, and
# telling them apart is the whole of the round-2 fail-closed defect: a scanner
# error that exits 1 is indistinguishable from a real finding about the
# workflow. `derived_says` is deliberately NOT used here - it aborts the script
# on rc >= 2, which is the correct behaviour under test.
printf 'jobs:\n  broken: [\n' >"$FIXDIR/malformed.yml"
derived_lane_covering platform/cmd/axonctl "$FIXDIR/malformed.yml" >/dev/null 2>&1
MALFORMED_RC=$?
if [ "$MALFORMED_RC" -ge 2 ]; then
  ok "fixture: a workflow the YAML scanner rejects exits $MALFORMED_RC (>= 2, an instrument failure) rather than 1 (a finding about the workflow)"
else
  bad "fixture: a malformed workflow exited $MALFORMED_RC, which the caller reads as \"no job runs this module\"; a scanner error would be published as a real finding"
fi

# A job that runs the module and is not wired into the summary is a job whose
# red does not stop anything. The summary is the check the mirror's own ruleset
# requires, so "runs" and "gates" are two different claims and both are needed.
#
# The program is held in a variable rather than inlined as a heredoc so the
# FIXTURES below can drive THIS code - not a re-implementation of it - against
# synthetic workflows. A test that rebuilds the thing under test tests a
# lookalike.
PY_WIRING="$(
  cat <<'PYW'
wf = sys.argv[1]
label = os.path.basename(wf)

# Rc 3, not 1, for a document the scanner rejects. Exit 1 is this program's
# spelling of "a real finding about the workflow", and a YAML mutant that breaks
# the document would otherwise die here and read as one (#3728 round 3).
try:
    with open(wf) as fh:
        doc = yaml.safe_load(fh)
except Exception as exc:  # noqa: BLE001 - deliberately broad; see above
    print("  FAIL: %s could not be parsed (%r), so the summary-wiring check did not run" % (label, exc))
    sys.exit(3)

jobs = doc.get("jobs", {})
summary = jobs.get("test-summary")
if summary is None:
    print("  FAIL: %s declares no test-summary job" % label)
    sys.exit(1)

needs = summary.get("needs") or []
if isinstance(needs, str):
    needs = [needs]

# The root-module lane. The three per-service steps reach three packages (and
# the connectors tree); this lane must reach the rest by DERIVATION, not by
# name, so a package added tomorrow is in it by default. What is asserted:
#   - a job whose run steps `cd platform` (the module root, not a package),
#   - selects with `go list ./...`,
#   - names platform/shared/identity as its canary (the package this lane was
#     created for; the job asserts at runtime that it is in the selection).
# The canary is matched in its ASSERTION form on non-comment lines only: the
# job comment explains the lane in terms of shared/identity, and a marker that
# matches prose is a marker that survives the deletion of the check it stands
# for.
CANARY = "/platform/shared/identity$'"
root_lane = None
for name, job in jobs.items():
    scripts = [code_lines(s.get("run")) for s in (job.get("steps") or [])]
    if any("cd platform\n" in s and "go list ./..." in s and CANARY in s for s in scripts):
        root_lane = name
        break
if root_lane is None:
    print("  FAIL: no job in %s tests the ROOT platform module by `go list ./...` from `cd platform` with the shared/identity canary;" % label)
    print("        every platform/shared/*, orchestrator/* and agent/* subpackage would mirror and never execute (#3574)")
    sys.exit(1)
print("  PASS: %s tests the root platform module by derivation (go list ./... with the shared/identity canary)" % root_lane)

# Every job that changes directory into a non-root platform module, plus the
# root-module lane, must gate the summary.
#
# "Changes directory into a module" has two spellings (#3728). A lane that
# DERIVES its members writes `cd "<var>"` inside a loop, and matching only the
# literal `cd platform/` would have quietly stopped counting the standalone
# lane the day it stopped listing its modules - the wiring assertion would go
# vacuous for exactly the job that had just changed, which is the failure this
# whole file exists to prevent.
#
# BOTH spellings are matched on code_lines() only, not on raw `run:` text
# (#3728 round 3). Round 2 added the derived spelling against the raw script, so
# a job whose only step mentioned `cd "$m"` and `go test ./...` inside two `#`
# comments was scored as running platform code and reported as ungated -
# reproduced, and it reds a required check on a correct workflow. The older
# `cd platform/` half had the same exposure and is fixed with it: the defect is
# the class "a marker matched against prose", not the one clause that showed it.
missing = []
for name, job in jobs.items():
    if name == "test-summary":
        continue
    runs_a_module = False
    for step in (job.get("steps") or []):
        code = code_lines(step.get("run"))
        names_a_module = "cd platform/" in code and "cd platform\n" not in code
        derives_modules = bool(CD_LOOP_VAR.search(code)) and "go test ./..." in code
        if names_a_module or derives_modules:
            runs_a_module = True
            break
    if not runs_a_module and name != root_lane:
        continue
    if name not in needs:
        missing.append(name)

if missing:
    print("  FAIL: these jobs run platform code and do not gate test-summary: %s" % ", ".join(sorted(missing)))
    sys.exit(1)

# `needs` is half of gating. The other half is the failure expression: the
# summary's "fail if any test failed" step reads `needs.<job>.result` for each
# job it gates on, and a job it never reads can be red without the summary
# noticing. The step is found by shape (an `if:` that reads a needs result
# and compares against 'success'), not by its display name.
fail_steps = [
    s for s in (summary.get("steps") or [])
    if "needs." in str(s.get("if") or "") and "!= 'success'" in str(s.get("if") or "")
]
if not fail_steps:
    print("  FAIL: test-summary has no step whose `if:` reads needs.*.result against 'success'; nothing fails the summary")
    sys.exit(1)
fail_expr = " ".join(str(s.get("if")) for s in fail_steps)
unread = [n for n in needs if ("needs.%s.result" % n) not in fail_expr]
if unread:
    print("  FAIL: these jobs are in test-summary's needs but its failure expression never reads their result: %s" % ", ".join(sorted(unread)))
    print("        A job the expression ignores can be red while the required check goes green.")
    sys.exit(1)

# Anti-vacuity: the loops above must have found something to check.
gating = [n for n in needs if n in jobs]
if len(gating) < 2:
    print("  FAIL: test-summary needs only %d known job(s); the wiring check is not looking at anything" % len(gating))
    sys.exit(1)

print("  PASS: every community job that runs platform code gates test-summary in both needs and the failure expression (%d jobs)" % len(gating))
PYW
)"

# summary_wiring_check <workflow> - run PY_WIRING against <workflow>.
summary_wiring_check() {
  printf '%s\n%s\n' "$PY_PRELUDE" "$PY_WIRING" | python3 - "$1"
}

summary_wiring_check "$COMMUNITY_WORKFLOW"
WIRING_RC=$?
if [ "$WIRING_RC" -eq 0 ]; then
  PASS=$((PASS + 1))
elif [ "$WIRING_RC" -eq 1 ]; then
  FAIL=$((FAIL + 1))
else
  echo "  FAIL: the summary-wiring check exited $WIRING_RC, so it did not run; a guard that cannot run must not pass"
  echo ""
  echo "  passed: $PASS   failed: $((FAIL + 1))"
  exit 1
fi

# ---------------------------------------------------------------------------
# FIXTURES for the summary-wiring half (#3728 round 3)
#
# Round 2's clause here was correct, load-bearing and UNPINNED: deleting it
# outright left this guard green at 8/8, and a behaviour-identical rename of the
# lane's loop variable re-vacuated it while emitting two false module findings.
# So each of the three properties gets a fixture, and the fixtures run the real
# PY_WIRING program rather than a re-implementation of its rules.
#
# Every fixture below declares a root lane that IS wired and a second wired job,
# so the earlier assertions and the >= 2 anti-vacuity floor are satisfied and the
# only variable is whether `subject-job` is scored as running platform code.
# ---------------------------------------------------------------------------

# write_wiring_fixture <outfile> <subject-kind>
#
# The workflow is emitted with yaml.safe_dump rather than templated as text, so
# a fixture can never be a YAML mutant that breaks the document and makes every
# assertion die with a scanner error - which reads as a kill and is not one.
write_wiring_fixture() {
  printf '%s\n%s\n' "$PY_PRELUDE" "$PY_FIXTURE" | python3 - "$1" "$2" "$COMMUNITY_WORKFLOW"
}

PY_FIXTURE="$(
  cat <<'PYF'
out, kind, real_wf = sys.argv[1], sys.argv[2], sys.argv[3]

ROOT_RUN = (
    "cd platform\n"
    "go list ./... > /tmp/pkgs\n"
    "grep -qE '/platform/shared/identity$' /tmp/pkgs\n"
)

if kind == "loop-m":
    subject = 'for m in $FOUND; do\n  (cd "$m" && go test ./... -count=1)\ndone\n'
elif kind == "loop-mod":
    subject = 'for mod in $FOUND; do\n  (cd "$mod" && go test ./... -count=1)\ndone\n'
elif kind == "comment-only":
    subject = (
        '# The standalone lane loops `cd "$m"` and runs `go test ./...` in each\n'
        "# discovered module. This job only prints a note.\n"
        'echo "note"\n'
    )
elif kind == "comment-only-named":
    subject = (
        "# This job used to `cd platform/decision` and run its gates; it does not\n"
        "# any more.\n"
        'echo "note"\n'
    )
elif kind == "real-lane":
    with open(real_wf) as fh:
        real = yaml.safe_load(fh)
    steps = real["jobs"]["unit-tests-standalone-modules"]["steps"]
    subject = "\n".join(str(s.get("run") or "") for s in steps)
    if "go test ./..." not in code_lines(subject):
        sys.exit("fixture builder: the real lane no longer contains `go test ./...`")
else:
    sys.exit("fixture builder: unknown kind %r" % kind)

fixture = {
    "name": "wiring fixture (%s)" % kind,
    "on": ["push"],
    "jobs": {
        "unit-tests-platform-packages": {"steps": [{"name": "root", "run": ROOT_RUN}]},
        "other-gated-job": {"steps": [{"name": "noop", "run": "echo hi\n"}]},
        "subject-job": {"steps": [{"name": "subject", "run": subject}]},
        "test-summary": {
            "needs": ["unit-tests-platform-packages", "other-gated-job"],
            "steps": [
                {
                    "name": "Fail if any test failed",
                    "if": (
                        "needs.unit-tests-platform-packages.result != 'success' || "
                        "needs.other-gated-job.result != 'success'"
                    ),
                    "run": "exit 1\n",
                }
            ],
        },
    },
}
with open(out, "w") as fh:
    yaml.safe_dump(fixture, fh, sort_keys=False)
PYF
)"

# wiring_fixture_names_subject <kind> - build the fixture, run the real wiring
# program over it, and succeed when it reports subject-job as ungated. The
# assertion is on the SPECIFIC diagnostic, not on the exit status: this program
# exits 1 for six different reasons, and a fixture that failed the root-lane
# assertion instead would otherwise read as a kill.
wiring_fixture_names_subject() {
  local kind="$1"
  local out
  out="$(write_wiring_fixture "$FIXDIR/wiring-$kind.yml" "$kind" 2>&1)" || {
    echo "  FAIL: the $kind fixture could not be built: $out"
    echo ""
    echo "  passed: $PASS   failed: $((FAIL + 1))"
    exit 1
  }
  out="$(summary_wiring_check "$FIXDIR/wiring-$kind.yml" 2>&1)"
  printf '%s\n' "$out" | grep -qF "do not gate test-summary: subject-job"
}

# PIN 1 - the clause must FIRE. Delete round 2's derived spelling and this dies:
# subject-job stops being scored as running platform code, the fixture workflow
# reports no finding, and the assertion below fails.
if wiring_fixture_names_subject loop-m; then
  ok "fixture: an UNWIRED lane that loops \`cd \"\$m\"\` + \`go test ./...\` is reported as ungating test-summary"
else
  bad "fixture: an unwired derived lane was NOT reported; the derived spelling in the wiring matcher has gone vacuous, which is the #3728 regression itself"
fi

# PIN 2 - and it must survive a rename of the loop variable, which is
# behaviour-identical and preserves twin parity.
if wiring_fixture_names_subject loop-mod; then
  ok "fixture: the same lane spelled \`cd \"\$mod\"\` is still reported (the matcher is not keyed on the variable name)"
else
  bad "fixture: renaming the loop variable hid an unwired derived lane from the wiring matcher"
fi

# PIN 3 - the strongest of the three, because its input is not a hand-written
# approximation of the lane: it is the REAL unit-tests-standalone-modules step
# text, lifted out of the parsed community workflow and dropped into an unwired
# fixture. An edit to the lane that the matcher cannot see reds this guard with a
# diagnostic naming the cause, instead of letting the wiring half go silently
# vacuous for the job that changed.
if wiring_fixture_names_subject real-lane; then
  ok "fixture: the REAL standalone-modules step text, placed in an unwired job, is recognised as running platform code"
else
  bad "fixture: the real standalone-modules step is no longer recognised by the wiring matcher; the lane changed shape and this half is vacuous for it"
fi

# PIN 4 and 5 - the FALSE-POSITIVE direction, which is the one that reds correct
# work on a required check. A job that only MENTIONS the markers in `#` comments
# runs no platform code and must not be reported. Both spellings are covered
# because the fix was to the class, not to the clause that showed it.
for kind in comment-only comment-only-named; do
  if wiring_fixture_names_subject "$kind"; then
    bad "fixture ($kind): a job whose markers appear only inside \`#\` comments was reported as running platform code; that reds a required check on a correct workflow"
  else
    ok "fixture ($kind): markers inside \`#\` comments do not make a job count as running platform code"
  fi
done

echo ""
echo "  passed: $PASS   failed: $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
