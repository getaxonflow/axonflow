#!/usr/bin/env bash
# Regression guard: the merge-queue selection manifest still covers what each
# suite depends on.
#
# THE BUG CLASS, and it is a merge hazard rather than an authoring one. Since
# the stack-booting suites lost their `pull_request` trigger, the ONLY thing
# that decides whether a suite runs in the merge queue is its entry in
# `.github/nightly-suite-paths.yml`, read by `.github/scripts/suite-relevant.py`.
# A PR that adds paths to a workflow's own `pull_request.paths` therefore
# conflicts with this branch's deletion of that block, and the natural
# resolution - take our side of the workflow - silently drops the additions.
# The suite then answers `relevant=false` for exactly the changes the other PR
# extended it to cover, and the board is green because nothing ran.
#
# WHAT THE INVARIANT IS NOT, and this is the part worth reading before editing
# this file. "The entry is non-empty" is NOT the property to check:
#
#     paths = (man.get("suites") or {}).get(suite)
#     if not paths:
#         return emit(True, "no manifest entry ...; failing open")
#
# A missing or emptied entry FAILS OPEN - the suite runs. That is expensive,
# never silent. The dangerous state is a list that is still non-empty and has
# quietly stopped covering something, because a non-empty list does not fail
# open: it is believed. So this guard checks COVERAGE, not emptiness.
#
# Three checks, in increasing specificity:
#   1. every suite with a `relevant` job has a manifest entry at all;
#   2. every such entry lists the suite's OWN workflow file - editing a
#      workflow must always select the suite it belongs to. This is the
#      GENERAL invariant and the one that catches the next relocation
#      without anyone re-deriving a path list by hand;
#   3. a pin on the paths from #3774 (#3762 typed authoring), which are the
#      concrete entries this class already tried to drop once.
#
# CENSUS AND FLOOR. 73 suites gate on the relevance job today, against a floor
# of 40. The floor exists because every check here is driven off that census:
# if a parse change stopped finding gated workflows, all three would pass by
# examining nothing, and the guard would report a confident clean over a tree
# it can no longer read. The floor is deliberately well below 73 - it is there
# to catch a census that has gone blind, not to pin the suite count, which
# moves whenever a suite is added or retired.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

MAN=.github/nightly-suite-paths.yml
[ -f "$MAN" ] || { echo "FAIL: manifest missing: $MAN"; exit 1; }

# The #3774 pin. These moved out of portal-parity-e2e.yml's pull_request.paths
# when the PR tier was removed; the manifest is where they live now.
PIN_SUITE=portal-parity-e2e.yml
read -r -d '' PIN_PATHS <<'PINS'
ee/platform/customer-portal/api/typed_authoring.go
ee/platform/customer-portal/api/typed_authoring_community.go
ee/platform/customer-portal/api/identity_org_settings.go
ee/platform/customer-portal/api/identity_org_settings_upsert.go
ee/platform/customer-portal/main.go
migrations/enterprise/154_identity_org_settings_typed_authoring.sql
platform/decision/authoring/**
platform/decision/conformance/**
platform/decision/pdp/**
platform/decision/contract/**
platform/shared/identity/**
ee/platform/customer-portal/middleware/**
PINS

check() {
  python3 - "$1" "$PIN_SUITE" "$PIN_PATHS" <<'PY'
import glob, io, os, sys, yaml

root, pin_suite, pin_blob = sys.argv[1], sys.argv[2], sys.argv[3]
pins = [p for p in pin_blob.split("\n") if p.strip()]
man = yaml.safe_load(io.open(os.path.join(root, ".github/nightly-suite-paths.yml"),
                             encoding="utf-8")) or {}
suites = man.get("suites") or {}
uncond = man.get("unconditional") or {}

# Census: workflows that gate on the relevance job. Those are the ones whose
# selection depends entirely on the manifest.
gated = []
for f in sorted(glob.glob(os.path.join(root, ".github/workflows/*.yml"))):
    try:
        d = yaml.safe_load(io.open(f, encoding="utf-8"))
    except Exception:
        continue
    if not isinstance(d, dict):
        continue
    for job in (d.get("jobs") or {}).values():
        if isinstance(job, dict) and str(job.get("uses", "")).endswith("suite-relevant.yml"):
            gated.append(os.path.basename(f))
            break

problems = []
for wf in gated:
    if wf in uncond:
        continue
    entry = suites.get(wf)
    if not entry:
        problems.append(("no-entry", wf, "gates on the relevance job but has no manifest entry"))
        continue
    if (".github/workflows/" + wf) not in entry:
        problems.append(("no-self", wf,
                         "does not list its own workflow file, so editing it selects nothing"))

if pin_suite in suites:
    have = set(suites[pin_suite] or [])
    for p in pins:
        if p not in have:
            problems.append(("pin", pin_suite, "lost the #3774 path " + p))
elif pin_suite in [g for g in gated]:
    problems.append(("pin", pin_suite, "has no manifest entry at all"))

print(len(gated))
for kind, wf, why in problems:
    print("%s\t%s\t%s" % (kind, wf, why))
PY
}

out=$(check .) || { echo "FAIL: census did not run"; exit 1; }
gated=$(printf '%s\n' "$out" | head -1)
problems=$(printf '%s\n' "$out" | tail -n +2 | sed '/^$/d')

if [ "${gated:-0}" -lt 40 ]; then
  echo "FAIL: only ${gated:-0} suites gate on the relevance job (floor 40) - the census is not reading the tree"
  exit 1
fi
echo "ok: censused ${gated} suites gated on the relevance job"

if [ -n "$problems" ]; then
  echo "FAIL: the merge-queue selection manifest no longer covers these suites:"
  printf '%s\n' "$problems" | sed 's/^/  /'
  echo ""
  echo "In the merge queue this manifest is the ONLY selection input. An entry"
  echo "that is present but incomplete does NOT fail open - it is believed, and"
  echo "the suite is skipped for the paths it stopped listing."
  echo ""
  echo "If a path genuinely no longer belongs, delete it from the pin in this"
  echo "test in the same diff, with the reason."
  exit 1
fi
echo "ok: every gated suite has an entry, lists its own workflow, and keeps the #3774 paths"

# --------------------------------------------------------------------------
# Controls. A census that only ever returns clean is indistinguishable from one
# that reads nothing, so both failure shapes are constructed and must be seen.
# --------------------------------------------------------------------------
tmp=$(mktemp -d) || exit 1
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/.github"
cp -R .github/workflows "$tmp/.github/workflows"

drop_one_pin() {
  python3 - "$1" <<'PY'
import io, re, sys
p = sys.argv[1] + "/.github/nightly-suite-paths.yml"
s = io.open(p, encoding="utf-8").read()
s = s.replace("  - platform/decision/pdp/**\n", "", 1)
io.open(p, "w", encoding="utf-8").write(s)
PY
}
cp "$MAN" "$tmp/.github/nightly-suite-paths.yml"
drop_one_pin "$tmp"
c1=$(check "$tmp" | tail -n +2 | grep -c 'lost the #3774 path platform/decision/pdp')
[ "$c1" -ge 1 ] && echo "ok: dropping ONE pinned path IS caught" || {
  echo "FAIL: a dropped pinned path went unnoticed - the pin is inert"; exit 1; }

cp "$MAN" "$tmp/.github/nightly-suite-paths.yml"
python3 - "$tmp" <<'PY'
import io, sys
p = sys.argv[1] + "/.github/nightly-suite-paths.yml"
s = io.open(p, encoding="utf-8").read()
s = s.replace("  - .github/workflows/portal-parity-e2e.yml\n", "", 1)
io.open(p, "w", encoding="utf-8").write(s)
PY
c2=$(check "$tmp" | tail -n +2 | grep -c 'does not list its own workflow file')
[ "$c2" -ge 1 ] && echo "ok: removing a suite's self-reference IS caught" || {
  echo "FAIL: a suite that no longer selects on its own workflow went unnoticed"; exit 1; }

cp "$MAN" "$tmp/.github/nightly-suite-paths.yml"
c3=$(check "$tmp" | tail -n +2 | sed '/^$/d' | wc -l | tr -d ' ')
[ "$c3" = "0" ] && echo "ok: the unmutated manifest reports clean" || {
  echo "FAIL: the guard fires on an unmodified tree"; check "$tmp" | tail -n +2; exit 1; }

echo "PASS: the merge-queue selection manifest still covers every gated suite"
