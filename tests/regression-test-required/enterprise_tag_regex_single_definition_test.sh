#!/usr/bin/env bash
# enterprise_tag_regex_single_definition_test.sh - #3574
#
# "Enterprise-only source" has ONE definition in this repository: the
# build-constraint scan the community sync runs before it publishes the mirror,
#
#     ^//go:build enterprise|^// \+build enterprise
#
# Every Go file it matches is deleted from the staged community copy. That
# expression is now read in eight places: the sync workflow, the leak gate, the
# mirror simulation, four Go tests that must know whether a file they cite will
# exist on the mirror (a census row for an enterprise-tagged file is absent
# there by construction, not deleted), and the capability registry's route and
# build-tag derivation, which classifies every file it parses. A classifier that drifts from the
# sync's expression classifies a DIFFERENT mirror - it would report a stripped
# file as deleted, or accept a leaked one as expected - and nothing else would
# notice, because each site compiles and passes on its own.
#
# THE RULE: the expression appears byte-identical at every site listed below,
# and every listed site exists. A site that stops carrying it is a site that
# has grown its own definition.
#
# Run: bash tests/regression-test-required/enterprise_tag_regex_single_definition_test.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT" || exit 1

# The literal, as it must appear in a shell single-quoted string and inside a
# Go raw-string literal (where the Go sites prefix it with (?m) for multi-line
# anchoring, which is the file-content equivalent of grep's per-line match).
LITERAL='^//go:build enterprise|^// \+build enterprise'

SITES=$'.github/workflows/sync-community-repo.yml
.github/scripts/check-enterprise-leak.sh
scripts/ci/simulate-community-mirror.sh
platform/shared/policy/legacy_call_site_census_test.go
platform/decision/registry/legacy_planes_test.go
platform/agent/hitl_twin_census_test.go
platform/shared/identity/conformance_registry_test.go
platform/shared/capability/derive.go'

# Go files the sweep below finds that are NOT classifiers of arbitrary source
# and so need not carry the sync's expression. `file :: reason`; each entry is
# load-bearing (the sweep must actually find the file, or the entry is stale).
EXEMPT_SITES=$'platform/shared/egress/conformance_test.go :: asserts that ONE named file has exactly the constraint line "//go:build enterprise", via buildConstraints() over that file; an equality on the canonical spelling of a known file, not a classifier deciding whether arbitrary source is enterprise-only
platform/shared/capability/derive_test.go :: writes synthetic Go files carrying the directive as FIXTURE INPUT to SourceEdition, the classifier that lives in derive.go and is on the list above; the strings here are the source being classified, not an expression deciding the classification
platform/shared/sdkcompat/no_second_copy_test.go :: writes synthetic Go sources carrying the directive as FIXTURE INPUT to a go/ast walk that searches for SDK-version map literals; the walk is deliberately NOT build-tag aware - a tagged file must be searched like any other, which is the property TestTheWalkIsNotBuildTagAware pins - so the strings here are the source being searched, never an expression deciding an edition'

# The mirror carries the five Go sites and nothing else on the list; this suite
# runs in the enterprise repository only, so all eight must be present here.
if [ ! -d ee ]; then
  echo "SKIP: community checkout; the sync-side sites do not exist on the mirror"
  exit 0
fi

PASS=0
FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

echo "=== the enterprise-source expression has exactly one definition ==="

count=0
while IFS= read -r site; do
  [ -n "$site" ] || continue
  count=$((count + 1))
  if [ ! -f "$site" ]; then
    bad "$site does not exist; the list in this test is stale or the site moved"
    continue
  fi
  n="$(grep -cF -- "$LITERAL" "$site" || true)"
  if [ "$n" -ge 1 ]; then
    ok "$site carries the sync's expression ($n occurrence(s))"
  else
    bad "$site does not carry the sync's expression verbatim; it has grown its own definition of enterprise-only source"
  fi
done <<< "$SITES"

# Anti-vacuity: the list must be the whole population, and the population is
# DERIVED, not counted by hand. Every Go file (test or not) under platform/ and
# ee/ that carries `go:build enterprise` inside a string literal - a backquoted
# raw string or a double-quoted string, wherever it is later compiled - is a
# site that classifies source by build constraint, whatever spelling it uses;
# the constraint line itself begins with `//` and is not a string, so it does
# not match. Every such file must be on the list, and every Go file on the
# list must be found by the sweep, so the two cannot drift apart in either
# direction.
# The bracket expression needs a LITERAL backtick: `\x60` is not an escape in
# ERE bracket expressions on either GNU or BSD grep (it is the four characters
# \ x 6 0, and "x" then matches the x in "matrix"), which is how the first
# version of this sweep flagged a comment line. Comment lines are excluded by
# line, not by file: the directive quoted in prose is not a classifier.
STRING_PAT=$'["`][^"`]*go:build enterprise[^"`]*["`]'
shape_hits="$(grep -rnE --include='*.go' -e "$STRING_PAT" platform ee 2>/dev/null | grep -vE '^[^:]+:[0-9]+:[[:space:]]*//' | cut -d: -f1 | sort -u || true)"
listed_go="$(grep -E '\.go$' <<< "$SITES" | sort -u)"
exempt_go="$(sed -n 's/ :: .*//p' <<< "$EXEMPT_SITES" | sort -u)"
if [ -z "$shape_hits" ]; then
  bad "the sweep found no Go file carrying the expression as a string; the sweep has stopped working"
fi
unlisted=0
while IFS= read -r f; do
  [ -n "$f" ] || continue
  if grep -qxF -- "$f" <<< "$exempt_go"; then
    continue
  fi
  if ! grep -qxF -- "$f" <<< "$listed_go"; then
    bad "$f carries a build-constraint expression as a string and is not on this test's list; add it (and make it carry the sync's literal), or exempt it with a reason if it is not a classifier"
    unlisted=$((unlisted + 1))
  fi
done <<< "$shape_hits"
while IFS= read -r f; do
  [ -n "$f" ] || continue
  if ! grep -qxF -- "$f" <<< "$shape_hits"; then
    bad "$f is exempted but the sweep does not find the expression in it; the exemption is stale"
    unlisted=$((unlisted + 1))
  elif grep -qxF -- "$f" <<< "$listed_go"; then
    bad "$f is both listed as a canonical site and exempted; one of the two is wrong"
    unlisted=$((unlisted + 1))
  else
    ok "$f is exempted with a reason: $(grep -F -- "$f :: " <<< "$EXEMPT_SITES" | sed 's/^[^:]* :: //' | cut -c1-90)"
  fi
done <<< "$exempt_go"
while IFS= read -r f; do
  [ -n "$f" ] || continue
  if ! grep -qxF -- "$f" <<< "$shape_hits"; then
    bad "$f is listed as a Go site but the sweep does not find the expression in it as a string; the list is stale"
    unlisted=$((unlisted + 1))
  fi
done <<< "$listed_go"
if [ "$unlisted" -eq 0 ]; then
  ok "the Go sites on the list are exactly the Go files the sweep finds ($(printf '%s\n' "$shape_hits" | grep -c .))"
fi

# Fixture self-test: the literal grep must fail on a near-miss, or a site could
# drift by a character and still pass.
tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
printf '%s\n' 'grep -rlE "^//go:build enterprise|^// +build enterprise"' > "$tmp"
if grep -qF -- "$LITERAL" "$tmp"; then
  bad "the literal match accepted a near-miss (unescaped +)"
else
  ok "a near-miss expression is not accepted as the definition"
fi

echo ""
echo "  passed: $PASS   failed: $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
