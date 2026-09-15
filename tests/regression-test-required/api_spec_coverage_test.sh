#!/usr/bin/env bash
# api_spec_coverage_test.sh - #2885, filed under #3818 (v11 lane W0-C)
#
# SUBJECT: scripts/ci/api-route-census.py, and through it the gap between the
# routes this repository REGISTERS and the routes its four OpenAPI specs
# DOCUMENT.
#
# THE DEBT. 450 registered API paths, 237 documented, **213 with no OpenAPI
# entry** - just under half the surface. Whole families - auth (16), the ADR-065 typed-policies
# surface (13), rbi (11), code-governance (9), organizations (8), sso (7), the
# SCIM 2.0 endpoints, decision-proof, `.well-known` - are served and written
# down nowhere. #2885 carried that as prose, and the figure on it was 59 days
# old, because nothing measured it.
#
# WHY A RATCHET RATHER THAN A THRESHOLD. 213 routes cannot be documented in one
# PR, and a guard that fails until they are is a guard somebody disables. A
# baseline that can only shrink converts the debt into a number with a
# direction: a PR that adds an undocumented route is red, and a PR that
# documents one must delete its row, so the file is the receipt.
#
# BOTH DIRECTIONS ARE CHECKED. A row that no longer corresponds to an
# undocumented route also fails - otherwise the baseline decays into a blanket
# exemption that outlives the routes it was written for, which is how an
# allowlist stops being an allowlist.
#
# WHAT THIS IS NOT. It is not path_template's TestTemplatesMatchAgentAPISpec,
# which is bidirectional, path-level, and covers `Templates` against
# agent-api.yaml alone - the reason the AGENT surface is in good shape and the
# reason nobody noticed the orchestrator and ee/ surfaces were not. It is not
# the capability registry's route guard either: that asks which EDITION serves a
# route, and a route can be perfectly classified and undocumented. This asks the
# third question - is it written down, at every method it answers.
#
# Run: bash tests/regression-test-required/api_spec_coverage_test.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CENSUS="$REPO_ROOT/scripts/ci/api-route-census.py"
BASELINE="$REPO_ROOT/tests/regression-test-required/lib/api-spec-coverage-baseline.tsv"

PASS=0
FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

if [ ! -d "$REPO_ROOT/docs/api" ] || [ ! -f "$REPO_ROOT/platform/shared/capability/registry.json" ]; then
  echo "SKIP: community checkout; the specs and the capability registry are not both present"
  exit 0
fi
[ -f "$CENSUS" ]   || { echo "  FAIL: $CENSUS is missing; this test cannot vacuously pass"; exit 1; }
[ -f "$BASELINE" ] || { echo "  FAIL: $BASELINE is missing; without it there is nothing to ratchet against"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 missing"; exit 1; }
python3 -c 'import yaml' 2>/dev/null || { echo "  FAIL: PyYAML missing; the census cannot parse the specs and must not pass without them"; exit 1; }

TMP="$(mktemp -d)" || { echo "  FAIL: mktemp -d"; exit 1; }
trap 'rm -rf "$TMP"' EXIT

python3 "$CENSUS" --root "$REPO_ROOT" --tsv > "$TMP/current.tsv" 2>"$TMP/err" || {
  bad "the census did not run: $(cat "$TMP/err")"
  echo; echo "PASS: $PASS  FAIL: $FAIL"; exit 1
}
grep -v '^#' "$BASELINE" | grep . | sort > "$TMP/baseline.sorted"
sort "$TMP/current.tsv" > "$TMP/current.sorted"

CUR=$(wc -l < "$TMP/current.sorted" | tr -d ' ')
BASE=$(wc -l < "$TMP/baseline.sorted" | tr -d ' ')
echo "undocumented routes: $CUR now, $BASE in the baseline"

if [ "$CUR" -lt 50 ]; then
  bad "the census reported only $CUR undocumented routes; it has ~213 to find, so it measured almost nothing"
fi

NEW=$(comm -23 "$TMP/current.sorted" "$TMP/baseline.sorted")
GONE=$(comm -13 "$TMP/current.sorted" "$TMP/baseline.sorted")

if [ -z "$NEW" ]; then
  ok "no route was registered without being documented"
else
  bad "route(s) registered with no OpenAPI entry and no baseline row:"
  echo "$NEW" | sed 's/^/      + /'
  echo "      Document them in docs/api/*.yaml, or - if the debt is deliberate -"
  echo "      add the row to $BASELINE and say why in the PR."
fi

if [ -z "$GONE" ]; then
  ok "every baseline row still corresponds to an undocumented route"
else
  bad "baseline row(s) that no longer name an undocumented route:"
  echo "$GONE" | sed 's/^/      - /'
  echo "      If you documented these, delete their rows - that is the ratchet turning."
  echo "      A row kept past its route is a standing exemption nobody asked for."
fi

# info.version tracks VERSION. Five documents describe one platform (the four
# under docs/api/ and the customer portal's under ee/docs/api/), and a
# per-spec version answered a question nobody asks: agent-api sat at 2.1.0 and
# orchestrator-api at 1.1.0 through 139 commits between them.
WANT="$(cat "$REPO_ROOT/VERSION")"
VERSION_BAD=0
for spec in "$REPO_ROOT"/docs/api/*.yaml "$REPO_ROOT"/ee/docs/api/*.yaml; do
  GOT="$(python3 -c "import yaml,sys; print(yaml.safe_load(open(sys.argv[1]))['info']['version'])" "$spec" 2>/dev/null)"
  if [ "$GOT" != "$WANT" ]; then
    bad "$(basename "$spec") info.version is '$GOT', VERSION is '$WANT'"
    VERSION_BAD=1
  fi
done
[ "$VERSION_BAD" -eq 0 ] && ok "every spec's info.version tracks VERSION ($WANT)"

# ---------------------------------------------------------------------------
# POSITIVE CONTROLS
# ---------------------------------------------------------------------------
seed() {
  rm -rf "$TMP/tree"; mkdir -p "$TMP/tree"
  for e in docs platform ee VERSION scripts tests; do
    [ -e "$REPO_ROOT/$e" ] && cp -R "$REPO_ROOT/$e" "$TMP/tree/$e"
  done
}

# 1. A new route registered with no spec entry must be caught.
seed
HANDLER="$TMP/tree/platform/orchestrator/census_control_handler.go"
cat > "$HANDLER" <<'GO'
package orchestrator

import "github.com/gorilla/mux"

func registerCensusControl(r *mux.Router) {
	r.HandleFunc("/api/v1/a-route-nobody-documented", nil).Methods("GET")
}
GO
python3 "$CENSUS" --root "$TMP/tree" --tsv 2>/dev/null | sort > "$TMP/mut.tsv"
if comm -23 "$TMP/mut.tsv" "$TMP/baseline.sorted" | grep -q 'a-route-nobody-documented'; then
  ok "control: a newly registered undocumented route is caught"
else
  bad "control: a newly registered undocumented route went UNDETECTED"
fi

# 2. Documenting a route must make its baseline row stale - the ratchet turning.
#    Uses a route that really is in the baseline today, chosen from the file rather
#    than named: the first version named /api/v1/auth/login, and the PR that
#    documented that route left this control with no subject. Any literal /api row
#    without path parameters will do, because the control writes its spec entry.
seed
VICTIM="$(grep -v '^#' "$BASELINE" | grep -E '^/api/[^{}	]*	' | head -1 | cut -f1)"
if [ -z "$VICTIM" ]; then
  bad "control: the baseline has no literal /api row without path parameters, so this control has no subject"
else
  python3 - "$TMP/tree/docs/api/orchestrator-api.yaml" "$VICTIM" <<'PY'
import sys, pathlib
spec, path = pathlib.Path(sys.argv[1]), sys.argv[2]
t = spec.read_text()
i = t.index("\npaths:\n") + len("\npaths:\n")
t = t[:i] + f"  {path}:\n    get:\n      summary: control\n      responses:\n        '200':\n          description: ok\n" + t[i:]
spec.write_text(t)
PY
  python3 "$CENSUS" --root "$TMP/tree" --tsv 2>/dev/null | sort > "$TMP/mut2.tsv"
  if comm -13 "$TMP/mut2.tsv" "$TMP/baseline.sorted" | grep -q "^${VICTIM}	"; then
    ok "control: documenting a route makes its baseline row stale (the ratchet turns)"
  else
    bad "control: documenting $VICTIM did not make its baseline row stale"
  fi
fi

# 3. A spec whose info.version drifts must be caught. The first version of this
# control planted the drift and then asserted `$GOT != $WANT` on the value it
# had just written - true by construction, and it never re-ran the check that is
# supposed to notice. A control that cannot fail is not a control.
seed
python3 - "$TMP/tree/docs/api/policy-api.yaml" <<'PY'
import sys, pathlib, re
p = pathlib.Path(sys.argv[1])
p.write_text(re.sub(r"^  version: .*$", "  version: 1.0.0", p.read_text(), count=1, flags=re.M))
PY
DRIFTED=0
for spec in "$TMP/tree"/docs/api/*.yaml "$TMP/tree"/ee/docs/api/*.yaml; do
  GOT="$(python3 -c "import yaml,sys; print(yaml.safe_load(open(sys.argv[1]))['info']['version'])" "$spec" 2>/dev/null)"
  [ "$GOT" != "$WANT" ] && DRIFTED=$((DRIFTED + 1))
done
if [ "$DRIFTED" -eq 1 ]; then
  ok "control: the info.version check reports exactly the one drifted spec"
else
  bad "control: the info.version check saw $DRIFTED drifted specs, expected exactly 1"
fi

# 4. And the reverse: with nothing planted, the same loop must report zero. Without
# this, a check that flagged every spec would pass control 3.
seed
CLEAN=0
for spec in "$TMP/tree"/docs/api/*.yaml "$TMP/tree"/ee/docs/api/*.yaml; do
  GOT="$(python3 -c "import yaml,sys; print(yaml.safe_load(open(sys.argv[1]))['info']['version'])" "$spec" 2>/dev/null)"
  [ "$GOT" != "$WANT" ] && CLEAN=$((CLEAN + 1))
done
if [ "$CLEAN" -eq 0 ]; then
  ok "control (negative): an unmutated tree reports no info.version drift"
else
  bad "control (negative): $CLEAN spec(s) reported drift on an unmutated tree"
fi

# 5. A route on a subrouter assigned in the same file is attributed to the path it
#    is SERVED at. The portal registers apiRouter.HandleFunc("/scim/tokens", ...)
#    under apiRouter := r.PathPrefix("/api/v1").Subrouter(). Read by its shape
#    alone that is "/scim/tokens", a path nothing serves, so documenting the real
#    route could never retire the row. The planted path starts with /scim for
#    exactly that reason: the shape heuristic calls it absolute.
seed
cat > "$TMP/tree/ee/platform/customer-portal/census_mount_control.go" <<'GO'
package main

import "github.com/gorilla/mux"

func registerCensusMountControl(r *mux.Router) {
	censusRouter := r.PathPrefix("/api/v1/census-mount").Subrouter()
	censusRouter.HandleFunc("/scim/leaf", nil).Methods("GET")
}
GO
python3 "$CENSUS" --root "$TMP/tree" --tsv 2>/dev/null > "$TMP/mut5.tsv"
if grep -q '^/api/v1/census-mount/scim/leaf	' "$TMP/mut5.tsv" && ! grep -q '^/scim/leaf	' "$TMP/mut5.tsv"; then
  ok "control: a route on a same-file subrouter is attributed to its served path"
else
  bad "control: a subrouter route was not attributed to /api/v1/census-mount/scim/leaf"
  grep -E 'census-mount|scim/leaf' "$TMP/mut5.tsv" | sed 's/^/      /'
fi

# 6. A route under an excluded scan root (a demo client backend) is not counted,
#    and the SAME registration under a product root is. Without the second half,
#    an exclusion that blinded the whole scan would pass this control.
seed
mkdir -p "$TMP/tree/ee/platform/clients/census-demo"
cat > "$TMP/tree/ee/platform/clients/census-demo/main.go" <<'GO'
package main

import "github.com/gorilla/mux"

func registerCensusDemoControl(r *mux.Router) {
	r.HandleFunc("/api/census-demo-only", nil).Methods("GET")
}
GO
python3 "$CENSUS" --root "$TMP/tree" --tsv 2>/dev/null > "$TMP/mut6a.tsv"
cp "$TMP/tree/ee/platform/clients/census-demo/main.go" "$TMP/tree/ee/platform/customer-portal/census_demo_control.go"
python3 "$CENSUS" --root "$TMP/tree" --tsv 2>/dev/null > "$TMP/mut6b.tsv"
if ! grep -q '^/api/census-demo-only	' "$TMP/mut6a.tsv" && grep -q '^/api/census-demo-only	' "$TMP/mut6b.tsv"; then
  ok "control: an excluded demo root is not counted, and the same route under a product root is"
else
  bad "control: the excluded-root classification is wrong (demo root counted, or product root missed)"
fi

# 7. A PathPrefix handler is a pattern. While nothing beneath it is documented it
#    is an undocumented row keyed on the prefix; once a spec documents a path
#    beneath it, the row is gone. Both halves, so a rule that dropped every
#    prefix would fail here.
seed
cat > "$TMP/tree/platform/agent/census_prefix_control.go" <<'GO'
package agent

import "github.com/gorilla/mux"

func registerCensusPrefixControl(r *mux.Router) {
	r.PathPrefix("/api/v1/census-proxy").HandlerFunc(nil).Methods("GET")
}
GO
python3 "$CENSUS" --root "$TMP/tree" --tsv 2>/dev/null > "$TMP/mut7a.tsv"
python3 - "$TMP/tree/ee/docs/api/portal-api.yaml" <<'PY'
import sys, pathlib
spec = pathlib.Path(sys.argv[1])
t = spec.read_text()
i = t.index("\npaths:\n") + len("\npaths:\n")
t = t[:i] + "  /api/v1/census-proxy/leaf:\n    get:\n      summary: control\n      responses:\n        '200':\n          description: ok\n" + t[i:]
spec.write_text(t)
PY
python3 "$CENSUS" --root "$TMP/tree" --tsv 2>/dev/null > "$TMP/mut7b.tsv"
if grep -q '^/api/v1/census-proxy	' "$TMP/mut7a.tsv" && ! grep -q '^/api/v1/census-proxy	' "$TMP/mut7b.tsv"; then
  ok "control: a PathPrefix handler is undocumented until a path beneath it is documented"
else
  bad "control: PathPrefix handler classification is wrong"
fi

echo
echo "PASS: $PASS  FAIL: $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
