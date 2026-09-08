#!/usr/bin/env bash
# docs_version_stamp_test.sh - #3818 (v11 lane W0-C, documentation state)
#
# SUBJECT: scripts/docs/stamp-docs-versions.py, and through it every version
# token in docs/ and technical-docs/ that states the CURRENT state of the tree.
#
# WHAT WENT WRONG. Measured 2026-09-07, with the platform at 10.4.0:
#   * 24 customer-facing docs/ pages stamped `**Platform Version:** 9.14.0 |
#     **SDK Version:** 9.0.0` - ten platform releases and three SDK minors of
#     drift, on the pages a customer reads first.
#   * Two tutorials ran `pip3 install axonflow==9.0.0` four lines above a Maven
#     block pinning 9.3.0. One page, two answers, and the new user gets the old
#     Python SDK.
#   * Five "latest released tag is 9.19.0" freshness notes, themselves stamped
#     2026-08-24, were five releases stale. A freshness note that is itself
#     stale is worse than none: it converts "I do not know how old this is" into
#     a confident wrong answer.
#   * technical-docs/README.md's platform-context line had been a full platform
#     minor and an SDK minor stale, and was hand-maintained.
#
# WHY THE GUARD IS "RUN THE GENERATOR AND REQUIRE NO DIFF" rather than its own
# copy of the rules: a guard holding a second copy of "what the current version
# is" is the same defect one level up. The generator reads `VERSION` and
# `platform/shared/sdkcompat/sdkcompat.go`; this test asserts the generator has
# nothing left to do. There is exactly one place that knows a version.
#
# WHAT IS DELIBERATELY NOT ENFORCED. A FACT is never rewritten and never
# checked: "Last verified 2026-08-24 against 9.19.0", "feature introduced in
# v9.9.0", "**Platform Version at verification:** 9.12.0", `Unreleased`.
# Rewriting one would fabricate the event it records. That is why the stale half
# of a freshness note is expressed as `current release X`, which IS derivable,
# leaving the verification date and version standing as the facts they are.
#
# Run: bash tests/regression-test-required/docs_version_stamp_test.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STAMPER="$REPO_ROOT/scripts/docs/stamp-docs-versions.py"

PASS=0
FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

if [ ! -d "$REPO_ROOT/technical-docs" ]; then
  echo "SKIP: community checkout; technical-docs/ is not mirrored and half the scope is absent"
  exit 0
fi
if [ ! -f "$STAMPER" ]; then
  echo "  FAIL: $STAMPER does not exist; this test cannot vacuously pass"
  exit 1
fi
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 missing; the stamper cannot run and this test must not pass without it"; exit 1; }

echo "== the real tree =="
OUT="$(python3 "$STAMPER" --check 2>&1)"; RC=$?
echo "$OUT" | sed 's/^/  /'
case $RC in
  0) ok "every derived version token matches VERSION and sdkcompat.go" ;;
  2) bad "the stamper found too few files to be checking anything" ;;
  *) bad "derived version tokens have drifted (run: python3 scripts/docs/stamp-docs-versions.py --write)" ;;
esac

# The generator must also be the thing that FIXES it. A --write that does not
# reach zero drift would leave every future author with an unfixable red.
TMP="$(mktemp -d)" || { echo "  FAIL: mktemp -d"; exit 1; }
trap 'rm -rf "$TMP"' EXIT

seed_copy() {                    # a minimal tree the stamper can run against
  rm -rf "$TMP/tree"; mkdir -p "$TMP/tree"
  cp "$REPO_ROOT/VERSION" "$TMP/tree/VERSION"
  mkdir -p "$TMP/tree/platform/shared/sdkcompat"
  cp "$REPO_ROOT/platform/shared/sdkcompat/sdkcompat.go" "$TMP/tree/platform/shared/sdkcompat/"
  cp -R "$REPO_ROOT/docs" "$TMP/tree/docs"
  cp -R "$REPO_ROOT/technical-docs" "$TMP/tree/technical-docs"
}

# control <name> <file-under-tree> <perl-expr> <expect-substring> <auto-repairable:yes|no>
#
# `auto-repairable=no` is not a weaker assertion, it is a different one: a drifted
# NUMBER is mechanically repairable and --write must fix it, while a stamp under
# the wrong LABEL is not - the generator cannot know whether the author meant the
# current state or a recorded fact. Requiring --write to "fix" that would be
# requiring it to guess. The control asserts it stays red instead.
control() {
  local name="$1" rel="$2" expr="$3" expect="$4" repairable="$5"
  seed_copy
  perl -0pi -e "$expr" "$TMP/tree/$rel" || { bad "control $name: mutation failed"; return; }
  local out rc
  out="$(python3 "$STAMPER" --check --root "$TMP/tree" 2>&1)"; rc=$?
  if [ $rc -ne 1 ] || ! echo "$out" | grep -q -- "$expect"; then
    bad "control: $name went UNDETECTED (rc=$rc)"
    echo "$out" | sed 's/^/      /'
    return
  fi
  ok "control: $name is caught"
  python3 "$STAMPER" --write --root "$TMP/tree" >/dev/null 2>&1
  if python3 "$STAMPER" --check --root "$TMP/tree" >/dev/null 2>&1; then
    if [ "$repairable" = yes ]; then
      ok "control: $name is repaired by --write"
    else
      bad "control: --write silently 'repaired' $name; it cannot know the author's intent and must leave it red"
    fi
  else
    if [ "$repairable" = no ]; then
      ok "control: $name stays red after --write, as it must (a human picks the label)"
    else
      bad "control: --write did not repair $name"
    fi
  fi
}

# 1. The 24-page cluster, reintroduced on one page.
control "a stale **Platform Version:** stamp" \
        docs/guides/proxy-mode.md \
        's/\*\*Platform Version:\*\* 10\.4\.0/**Platform Version:** 9.14.0/' \
        "Platform Version 9.14.0" yes
# 2. The SDK half of the same header.
control "a stale **SDK Version:** stamp" \
        docs/guides/proxy-mode.md \
        's/\*\*SDK Version:\*\* 9\.3\.0/**SDK Version:** 9.0.0/' \
        "SDK 9.0.0" yes
# 3. The tutorial pin a new user copies.
control "a stale pip install pin" \
        docs/tutorials/README.md \
        's/axonflow==9\.3\.0/axonflow==9.0.0/' \
        "axonflow==9.0.0" yes
# 4. A freshness note that has gone stale.
control "a stale 'current release' freshness note" \
        technical-docs/ARCHITECTURE.md \
        's/current release 10\.4\.0/current release 9.19.0/i' \
        "current release 9.19.0" yes

# 5. THE SWAP. A stamp that dodges the canonical label is invisible to every
# control above - and four pages had already done it, three of them reaching a
# state where the SDK half had been stamped and the platform half had not, so
# the page contradicted itself AND passed. A guard that greps for one shape must
# be able to see the swap into another.
control "a version stamp that dodges the canonical label" \
        docs/guides/proxy-mode.md \
        's/\*\*Platform Version:\*\* 10\.4\.0/**Platform:** 9.14.0/' \
        "UNCANONICAL" no

# 6. The published specs' `info.version`. Four documents describe one platform,
# and a per-spec version answered a question nobody asks: agent-api sat at 2.1.0
# and orchestrator-api at 1.1.0 through 139 commits between them. This token is
# derived like any other - which matters because a sibling guard ASSERTS it, and
# an assertion with no writer means hand-editing exactly what a script exists to
# stop anyone hand-editing.
control "a drifted OpenAPI info.version" \
        docs/api/policy-api.yaml \
        's/^  version: 10\.4\.0$/  version: 2.1.0/m' \
        "info.version 2.1.0" yes

# 7. A DIVERGENT SDK MAP MUST REFUSE, NOT PICK. The docs carry a shared
# `**SDK Version:** X` stamp beside a list of all four stable SDKs, and that
# shape is only truthful while the four agree. An earlier version of the
# stamper took `sdks["go"]` and would have written 9.3.0 over a line naming
# Python while repairing the `pip install axonflow==` pins on the same page -
# the page contradicting itself, with the guard green.
seed_copy
perl -pi -e 's/"python":     "9\.3\.0"/"python":     "9.3.1"/' \
  "$TMP/tree/platform/shared/sdkcompat/sdkcompat.go"
DOUT="$(python3 "$STAMPER" --check --root "$TMP/tree" 2>&1)"; DRC=$?
if [ $DRC -ne 0 ] && echo "$DOUT" | grep -q 'no longer share a version'; then
  ok "control: a divergent SDK map refuses rather than stamping one language over the others"
else
  bad "control: a divergent SDK map did not refuse (rc=$DRC)"
  echo "$DOUT" | sed 's/^/      /'
fi

# A FACT must survive the generator untouched: this is the control for the
# rule that stops --write from fabricating a verification that never happened.
seed_copy
python3 "$STAMPER" --write --root "$TMP/tree" >/dev/null 2>&1
if grep -q '\*\*Platform Version at verification:\*\* 9\.12\.0' \
     "$TMP/tree/docs/reference/secrets-logging-checklist.md" &&
   grep -q 'Last verified:\*\* 2026-08-24 against v9\.19\.0' \
     "$TMP/tree/technical-docs/WCP_RETRY_IDEMPOTENCY_WIRE_CONTRACT.md" &&
   grep -q 'feature introduced in v9\.9\.0' \
     "$TMP/tree/docs/security/identity-header-trust.md"; then
  ok "control: --write leaves recorded facts (verification stamp, last-verified version, introduced-in) untouched"
else
  bad "control: --write rewrote a recorded fact - it is fabricating a verification"
fi

echo
echo "PASS: $PASS  FAIL: $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
