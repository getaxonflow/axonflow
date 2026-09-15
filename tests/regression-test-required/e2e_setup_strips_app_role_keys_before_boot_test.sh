#!/usr/bin/env bash
# Regression test for #4225's boot hazard: scripts/setup-e2e-testing.sh must
# boot phase 1 without the app-role keys an earlier production-posture boot left
# in the git-ignored .env.
#
# The bug: restart_services_with_app_role (production-posture phase 2) appends
# AXONFLOW_DB_USE_APP_ROLE=true and the two app-role DSNs to .env, and it
# stripped old copies only there, just before appending. A second local boot
# from the same checkout therefore started phase 1 (start_enterprise) already in
# app-role mode, on a fresh database whose axonflow_app_role has no password
# yet, and agent and portal crash-looped on:
#
#   pq: password authentication failed for user "axonflow_app_role"
#
# Measured twice on 2026-09-13 (W3-U, #4225): two boots from one checkout after
# a clean first one. CI boots from a fresh checkout, so it never saw this.
#
# This test has three parts, and they fail for three different regressions:
#
#   1. Behavioural: strip_production_posture_env_keys() and sed_inplace() are
#      EXTRACTED FROM the shipped script (never re-pasted here, where a copy
#      would drift) and driven over a realistic .env. Exactly the three keys
#      go; a look-alike key and a commented line stay byte for byte; an absent
#      .env stays absent.
#   2. Order: start_enterprise() unsets the three keys a sourced env file
#      exports and calls the helper, both before its first
#      `docker compose ... up`, and restart_services_with_app_role() calls it
#      before it appends. Each must be a top-level line of the function, so a
#      call wrapped in `if false` does not count. A helper that exists but runs
#      after the boot is the bug again.
#   3. Anti-vacuity: the same order check, run over a copy of the shipped
#      script with start_enterprise's call deleted (the unfixed boot order),
#      must report it. If it did not, part 2 would be passing on anything.
#
# Run locally:
#   bash tests/regression-test-required/e2e_setup_strips_app_role_keys_before_boot_test.sh

set -uo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
SETUP_SCRIPT="${REPO_ROOT}/scripts/setup-e2e-testing.sh"
fail=0

if [ ! -f "${SETUP_SCRIPT}" ]; then
  echo "FAIL: ${SETUP_SCRIPT} not found"
  exit 1
fi

# --- 1. Behavioural: exactly the three keys go -----------------------------

WORK="$(mktemp -d)"
HELPERS="${WORK}/helpers.sh"
awk '/^sed_inplace\(\) \{/,/^\}/' "${SETUP_SCRIPT}" > "${HELPERS}"
awk '/^strip_production_posture_env_keys\(\) \{/,/^\}/' "${SETUP_SCRIPT}" >> "${HELPERS}"
if ! grep -q '^sed_inplace() {' "${HELPERS}" || ! grep -q '^strip_production_posture_env_keys() {' "${HELPERS}"; then
  echo "FAIL: could not extract sed_inplace() and strip_production_posture_env_keys() from the setup script"
  exit 1
fi
# shellcheck disable=SC1090
. "${HELPERS}"

cat > "${WORK}/.env" <<'EOF'
DEPLOYMENT_MODE=saas
AXONFLOW_DB_USE_APP_ROLE=true
ORG_ID=a1b2c3d4-e5f6-7890-abcd-ef1234567890
AXONFLOW_DB_APP_ROLE_URL=postgres://axonflow_app_role:pw@postgres:5432/axonflow?sslmode=disable
AXONFLOW_DB_PLATFORM_ADMIN_URL=postgres://axonflow_platform_admin:pw@postgres:5432/axonflow?sslmode=disable
AXONFLOW_DB_USE_APP_ROLE_NOTE=a look-alike key stays
# AXONFLOW_DB_USE_APP_ROLE=true in a comment stays
TRAILING=keepme
EOF
cat > "${WORK}/want.env" <<'EOF'
DEPLOYMENT_MODE=saas
ORG_ID=a1b2c3d4-e5f6-7890-abcd-ef1234567890
AXONFLOW_DB_USE_APP_ROLE_NOTE=a look-alike key stays
# AXONFLOW_DB_USE_APP_ROLE=true in a comment stays
TRAILING=keepme
EOF

if ( REPO_ROOT="${WORK}"; strip_production_posture_env_keys ) && cmp -s "${WORK}/want.env" "${WORK}/.env"; then
  echo "ok: exactly the three app-role keys are stripped, every other line kept byte for byte"
else
  echo "FAIL: strip_production_posture_env_keys() did not leave exactly the expected .env:"
  diff "${WORK}/want.env" "${WORK}/.env" | sed 's/^/    /'
  fail=1
fi

NOENV="${WORK}/no-env"
mkdir "${NOENV}" || exit 1
if ( REPO_ROOT="${NOENV}"; strip_production_posture_env_keys ) && [ ! -e "${NOENV}/.env" ]; then
  echo "ok: an absent .env stays absent, and the helper succeeds"
else
  echo "FAIL: with no .env the helper failed or created one"
  fail=1
fi

# --- 2. Order: before the boot, and before the append ----------------------

# body_line <script> <function> <fixed string> [line]: the line number of the
# first non-comment line in <function>'s body that contains <fixed string>.
# With "line", the line must BE the string at the body's top-level indent (four
# spaces), so a call wrapped in `if false; then ...; fi` does not count.
body_line() {
  awk -v fn="$2" -v needle="$3" -v whole="${4:-}" '
    $0 ~ "^" fn "\\(\\) \\{" { inside = 1; next }
    inside && /^\}/ { exit }
    inside && $0 !~ /^[[:space:]]*#/ && ((whole == "line" && $0 == "    " needle) || (whole != "line" && index($0, needle))) { print NR; exit }
  ' "$1"
}

# order_ok <script> <function> <first> <after>: succeeds when <first> is a
# top-level line of <function>'s body, before a line containing <after>.
order_ok() {
  local first after
  first="$(body_line "$1" "$2" "$3" line)"
  after="$(body_line "$1" "$2" "$4")"
  [ -n "${first}" ] && [ -n "${after}" ] && [ "${first}" -lt "${after}" ]
}

BOOT='docker-compose.enterprise.yml up -d'
APPEND='} >> "${REPO_ROOT}/.env"'

if order_ok "${SETUP_SCRIPT}" start_enterprise strip_production_posture_env_keys "${BOOT}"; then
  echo "ok: start_enterprise strips the keys before it boots"
else
  echo "FAIL: start_enterprise() does not call strip_production_posture_env_keys before \"${BOOT}\""
  fail=1
fi
UNSET='unset AXONFLOW_DB_USE_APP_ROLE AXONFLOW_DB_APP_ROLE_URL AXONFLOW_DB_PLATFORM_ADMIN_URL'
if order_ok "${SETUP_SCRIPT}" start_enterprise "${UNSET}" "${BOOT}"; then
  echo "ok: start_enterprise unsets the exported app-role keys before it boots"
else
  echo "FAIL: start_enterprise() does not unset the three app-role keys before \"${BOOT}\"; a shell that sourced /tmp/axonflow-e2e-env.sh exports them, and compose prefers the environment over .env"
  fail=1
fi
if order_ok "${SETUP_SCRIPT}" restart_services_with_app_role strip_production_posture_env_keys "${APPEND}"; then
  echo "ok: phase 2 strips the keys before it appends them"
else
  echo "FAIL: restart_services_with_app_role() does not call strip_production_posture_env_keys before it appends"
  fail=1
fi

# --- 3. Anti-vacuity: the order check reports the unfixed boot order -------

UNFIXED="${WORK}/unfixed-setup.sh"
awk '
  /^start_enterprise\(\) \{/ { inside = 1 }
  inside && /^\}/ { inside = 0 }
  inside && /^[[:space:]]*strip_production_posture_env_keys[[:space:]]*$/ { next }
  { print }
' "${SETUP_SCRIPT}" > "${UNFIXED}"
shipped_lines="$(wc -l < "${SETUP_SCRIPT}" | tr -d ' ')"
unfixed_lines="$(wc -l < "${UNFIXED}" | tr -d ' ')"
if [ "${unfixed_lines}" -ne $((shipped_lines - 1)) ]; then
  echo "FAIL: the unfixed copy should be the shipped script minus one call line (shipped ${shipped_lines}, copy ${unfixed_lines})"
  fail=1
elif order_ok "${UNFIXED}" start_enterprise strip_production_posture_env_keys "${BOOT}"; then
  echo "FAIL: the order check passed a start_enterprise() with no pre-boot strip; part 2 is not discriminating"
  fail=1
else
  echo "ok: the order check reports the unfixed boot order (test is not vacuous)"
fi

if [ "${fail}" -eq 0 ]; then
  echo "PASS: production-posture app-role keys never reach a phase-1 boot (#4225)"
else
  echo "FAIL: see above"
  exit 1
fi
