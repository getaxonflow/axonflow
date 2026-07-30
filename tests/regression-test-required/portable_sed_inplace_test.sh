#!/usr/bin/env bash
# Regression test for #3094 — scripts/setup-e2e-testing.sh must edit files
# in place portably, not with the BSD-only `sed -i ''` form.
#
# The bug: `sed -i '' EXPR FILE` is BSD/macOS syntax. GNU sed (ubuntu-latest)
# takes no argument to -i, so it parsed '' as the sed script and EXPR as a
# filename and aborted the whole setup script:
#
#   sed: can't read s/DEPLOYMENT_MODE=.*/DEPLOYMENT_MODE=enterprise/:
#        No such file or directory
#
# It never reproduced for anyone developing on macOS, which is why it survived
# in the mandated E2E setup path.
#
# This test has three parts, and they fail for three different regressions:
#
#   1. Static: no `sed -i` of ANY spelling reappears in the setup script.
#      Catches a re-introduction by copy-paste even on a macOS-only run, where
#      the behavioural half of this test would happily pass.
#   2. Behavioural: the sed_inplace() helper is EXTRACTED FROM the shipped
#      script (never re-pasted here — a copy would drift and then prove
#      nothing) and driven over a realistic .env. Assertions are on FILE
#      CONTENT, not on sed's exit status: the original bug is a substitution
#      that does not happen, and a test that only checks `$?` would also pass
#      against a no-op edit.
#   3. Anti-vacuity: under GNU sed, the OLD form must still fail. If that ever
#      starts passing, part 2 has stopped discriminating and this test is no
#      longer evidence of anything.
#
# Run locally:
#   bash tests/regression-test-required/portable_sed_inplace_test.sh

set -uo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
SETUP_SCRIPT="${REPO_ROOT}/scripts/setup-e2e-testing.sh"
fail=0

if sed --version >/dev/null 2>&1; then
  SED_FLAVOUR="gnu"
else
  SED_FLAVOUR="bsd"
fi
echo "sed flavour under test: ${SED_FLAVOUR}"

if [ ! -f "${SETUP_SCRIPT}" ]; then
  echo "FAIL: ${SETUP_SCRIPT} not found"
  exit 1
fi

# --- 1. Static: no `sed -i` in any spelling --------------------------------

# Matches `sed -i`, `sed -i ''`, `sed -i.bak` and `sed -itmp`. The portable
# helper needs none of them, so any hit is a re-introduction of the class.
if grep -nE "(^|[^[:alnum:]_])sed[[:space:]]+-i" "${SETUP_SCRIPT}" \
     | grep -v '^[0-9]*:[[:space:]]*#'; then
  echo "FAIL: setup-e2e-testing.sh reintroduced 'sed -i' (see hits above)."
  echo "      Use sed_inplace() — \`sed -i ''\` is BSD-only and kills the"
  echo "      script on ubuntu-latest; a host-OS branch is the same bug."
  fail=1
else
  echo "ok: no 'sed -i' in setup-e2e-testing.sh"
fi

if ! grep -q "^sed_inplace() {" "${SETUP_SCRIPT}"; then
  echo "FAIL: sed_inplace() helper is gone from setup-e2e-testing.sh"
  exit 1
fi
echo "ok: sed_inplace() helper present"

# --- 2. Behavioural: substitutions actually land ---------------------------

WORK="$(mktemp -d)"
HELPER="${WORK}/sed_inplace.sh"
awk '/^sed_inplace\(\) \{/,/^\}/' "${SETUP_SCRIPT}" > "${HELPER}"
if [ ! -s "${HELPER}" ]; then
  echo "FAIL: could not extract sed_inplace() from the setup script"
  exit 1
fi
# shellcheck disable=SC1090
. "${HELPER}"

DEMO_ORG_ID="6f1c2d84-0a1b-4c9e-9f10-2b3c4d5e6f70"
ENVFILE="${WORK}/.env"
cat > "${ENVFILE}" <<EOF
LLM_API_KEY=sk-test
DEPLOYMENT_MODE=community
ORG_ID=stale-org
AXONFLOW_DB_USE_APP_ROLE=true
AXONFLOW_DB_APP_ROLE_URL=postgres://old
AXONFLOW_DB_PLATFORM_ADMIN_URL=postgres://oldadmin
TRAILING=keepme
EOF

# The five call sites in the setup script, verbatim in form.
sed_inplace 's/DEPLOYMENT_MODE=.*/DEPLOYMENT_MODE=enterprise/' "${ENVFILE}"
sed_inplace "s/ORG_ID=.*/ORG_ID=${DEMO_ORG_ID}/" "${ENVFILE}"
sed_inplace '/^AXONFLOW_DB_USE_APP_ROLE=/d' "${ENVFILE}"
sed_inplace '/^AXONFLOW_DB_APP_ROLE_URL=/d' "${ENVFILE}"
sed_inplace '/^AXONFLOW_DB_PLATFORM_ADMIN_URL=/d' "${ENVFILE}"

assert_content() { # assert_content <label> <regex> <want_found:0|1>
  if grep -qE "$2" "${ENVFILE}"; then found=1; else found=0; fi
  if [ "${found}" != "$3" ]; then
    echo "FAIL: $1 (found=${found} want=$3)"
    fail=1
  else
    echo "ok: $1"
  fi
}

assert_content "DEPLOYMENT_MODE rewritten to enterprise" '^DEPLOYMENT_MODE=enterprise$' 1
assert_content "old DEPLOYMENT_MODE value gone"          '^DEPLOYMENT_MODE=community$' 0
assert_content "ORG_ID rewritten to the demo uuid"       "^ORG_ID=${DEMO_ORG_ID}$" 1
assert_content "old ORG_ID value gone"                   '^ORG_ID=stale-org$' 0
assert_content "AXONFLOW_DB_USE_APP_ROLE deleted"        '^AXONFLOW_DB_USE_APP_ROLE=' 0
assert_content "AXONFLOW_DB_APP_ROLE_URL deleted"        '^AXONFLOW_DB_APP_ROLE_URL=' 0
assert_content "AXONFLOW_DB_PLATFORM_ADMIN_URL deleted"  '^AXONFLOW_DB_PLATFORM_ADMIN_URL=' 0
assert_content "unrelated first line preserved"          '^LLM_API_KEY=sk-test$' 1
assert_content "unrelated last line preserved"           '^TRAILING=keepme$' 1

# The helper must not litter the directory it edits in.
strays="$(find "${WORK}" -maxdepth 1 -name '.env.*' | wc -l | tr -d ' ')"
if [ "${strays}" != "0" ]; then
  echo "FAIL: sed_inplace left ${strays} temp file(s) beside the target"
  fail=1
else
  echo "ok: no temp files left behind"
fi

# --- 3. Anti-vacuity: the old form still breaks under GNU sed --------------

if [ "${SED_FLAVOUR}" = "gnu" ]; then
  printf 'DEPLOYMENT_MODE=community\n' > "${WORK}/old.env"
  if sed -i '' 's/DEPLOYMENT_MODE=.*/DEPLOYMENT_MODE=enterprise/' "${WORK}/old.env" 2>/dev/null \
     && grep -q '^DEPLOYMENT_MODE=enterprise$' "${WORK}/old.env"; then
    echo "FAIL: \`sed -i ''\` succeeded under GNU sed — this test no longer"
    echo "      discriminates between the broken and the fixed form."
    fail=1
  else
    echo "ok: \`sed -i ''\` still fails under GNU sed (test is not vacuous)"
  fi
else
  echo "skip: anti-vacuity check needs GNU sed (BSD accepts the old form by design)"
fi

if [ "${fail}" -eq 0 ]; then
  echo "PASS: portable in-place sed (#3094)"
else
  echo "FAIL: portable in-place sed (#3094)"
fi
exit "${fail}"
