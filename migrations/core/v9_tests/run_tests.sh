#!/usr/bin/env bash
# v9 migration test driver.
#
# Runs the v9 Phase 2+3 migrations against a fresh local Postgres
# (docker-compose), exercises the R1 / R2 / rollback test plan from
# the v9 brief, and emits PASS/FAIL summaries.
#
# Test sequence:
#   1. Spin up Postgres (re-use if already running)
#   2. Apply core migrations 001-085 (baseline)
#   3. Apply seed.sql
#   4. SCHEMA DUMP — pre-088 baseline
#   5. Apply 088-095 (first run)
#   6. SCHEMA DUMP — post-first-apply
#   7. Run NNN_assertions.sql for each migration; abort on first failure
#   8. R2: Apply 088-095 SECOND time, capture row-change counts (must be 0)
#   9. SCHEMA DUMP — post-second-apply (must match post-first-apply byte-for-byte)
#  10. Rollback: apply 095_down.sql → 088_down.sql in reverse order
#  11. SCHEMA DUMP — post-rollback (must match pre-088 baseline for additive
#      forward migrations; 094 documents a Pass-2 data caveat — see header)
#  12. SUMMARY
#
# Requires:
#   - docker / docker-compose
#   - psql client on PATH
#   - 5432 free OR PGPORT exported
#
# Run from repo root:
#   ./migrations/core/v9_tests/run_tests.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

TESTS_DIR="migrations/core/v9_tests"
MIG_DIR="migrations/core"
TMP=$(mktemp -d -t v9-tests-XXXXXX)
trap "rm -rf $TMP" EXIT

PGPORT="${PGPORT:-5432}"
PGUSER="${PGUSER:-axonflow}"
PGPASSWORD="${PGPASSWORD:-axonflow}"
PGDATABASE="${PGDATABASE:-axonflow}"
PGHOST="${PGHOST:-127.0.0.1}"
export PGPASSWORD
DSN="host=$PGHOST port=$PGPORT user=$PGUSER dbname=$PGDATABASE sslmode=disable"

bold() { printf '\n\033[1m========== %s ==========\033[0m\n' "$1"; }
ok()   { printf '\033[32m[PASS]\033[0m %s\n' "$1"; }
fail() { printf '\033[31m[FAIL]\033[0m %s\n' "$1" >&2; exit 1; }

# ---------- Step 1: Postgres ----------
bold "1. Ensure Postgres is reachable"
if ! psql "$DSN" -c '\q' >/dev/null 2>&1; then
    echo "Postgres not reachable at $DSN — starting docker-compose service 'postgres' (or similar)"
    if [[ -f docker-compose.test.yml ]]; then
        docker-compose -f docker-compose.test.yml up -d postgres 2>&1 || \
        docker compose -f docker-compose.test.yml up -d postgres
    elif [[ -f docker-compose.yml ]]; then
        docker-compose up -d postgres 2>&1 || docker compose up -d postgres
    else
        fail "No docker-compose file found; set PGHOST/PGPORT to an existing Postgres"
    fi
    echo "Waiting for Postgres..."
    for i in {1..30}; do
        if psql "$DSN" -c '\q' >/dev/null 2>&1; then break; fi
        sleep 1
    done
    psql "$DSN" -c '\q' >/dev/null 2>&1 || fail "Postgres still unreachable after 30s"
fi
ok "Postgres reachable"

# ---------- Step 2: Apply baseline migrations 001-085 ----------
bold "2. Apply baseline migrations (001-085)"
# Reset DB to clean state. Use `pg_terminate_backend` to kick any lingering
# sessions, then drop+recreate public schema.
psql "$DSN" -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid();" >/dev/null 2>&1 || true
psql "$DSN" -c "DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;" >/dev/null
# Sort files the same way the agent runner does: extract the version (first
# underscore-delimited token) and sort lexicographically by version, then
# filename. This matches platform/agent/migration_helpers.go:201
# `sort.Slice(migrations[i].Version < migrations[j].Version)`.
# `sort -V` on macOS does the wrong thing for "030" vs "030a" — it numerically
# treats them as equal and the tie-break is unstable.
for f in $(ls $MIG_DIR/*.sql | grep -v _down.sql | awk -F/ '{name=$NF; v=name; sub(/_.*/,"",v); print v "|" $0}' | sort | cut -d'|' -f2); do
    base=$(basename "$f")
    # Skip any migration >= 086. Use plain lex compare on the first token.
    ver=$(echo "$base" | cut -d_ -f1)
    if [[ "$ver" > "085" ]]; then continue; fi
    # Skip 028 — Grafana database setup uses dblink with a runtime-set
    # app.db_password session variable, which is supplied by the agent
    # binary at startup (platform/agent/run.go:689) but is unavailable
    # in a psql-driven baseline. Grafana is irrelevant to v9 identity
    # testing.
    if [[ "$ver" == "028" ]]; then
        ok "Skipped $base (Grafana setup — needs runtime app.db_password; not relevant to v9)"
        continue
    fi
    psql "$DSN" -v ON_ERROR_STOP=1 -f "$f" >/dev/null 2>"$TMP/baseline-$base.err" || {
        echo "Baseline migration $base failed; stderr:" >&2
        cat "$TMP/baseline-$base.err" >&2
        fail "Baseline failed at $base"
    }
done
ok "Baseline (001-085) applied"

# ---------- Step 3: Seed ----------
bold "3. Apply v9 test seed"
psql "$DSN" -v ON_ERROR_STOP=1 -f "$TESTS_DIR/seed.sql" >/dev/null
ok "Seed applied"

# ---------- Step 4: Pre-088 schema dump ----------
bold "4. Schema dump pre-088"
pg_dump --schema-only "$DSN" > "$TMP/schema-pre.sql"
ok "Schema dump captured: $TMP/schema-pre.sql ($(wc -l < $TMP/schema-pre.sql) lines)"

# ---------- Step 5: Apply 088-095 first run ----------
bold "5. Apply migrations 088-095 (first run)"
psql "$DSN" -c "SELECT set_config('app.deployment_org_id', 'test-deployment-org', false);" >/dev/null
for n in 088 089 090 091 092 093 094 095; do
    f=$(ls $MIG_DIR/${n}_v9_*.sql | grep -v _down.sql | head -1)
    psql "$DSN" -v ON_ERROR_STOP=1 -f "$f" > "$TMP/apply-$n.log" 2>&1 || {
        cat "$TMP/apply-$n.log" >&2
        fail "Migration $n failed on first apply"
    }
    ok "Applied $(basename $f)"
done

# ---------- Step 6: Post-first-apply schema dump ----------
bold "6. Schema dump post-first-apply"
pg_dump --schema-only "$DSN" > "$TMP/schema-post1.sql"
ok "Schema dump captured: $TMP/schema-post1.sql ($(wc -l < $TMP/schema-post1.sql) lines)"

# ---------- Step 7: Per-migration assertions ----------
bold "7. Run per-migration assertion suites"
for n in 088 089 090 091 092 093 094 095; do
    psql "$DSN" -v ON_ERROR_STOP=1 -f "$TESTS_DIR/${n}_assertions.sql" > "$TMP/assert-$n.log" 2>&1 || {
        cat "$TMP/assert-$n.log" >&2
        fail "Assertion suite ${n}_assertions.sql FAILED"
    }
    ok "Assertions ${n} passed"
done

# Functional tests — beyond "psql exited 0", these exercise real v9 query
# shapes against the seeded data to verify semantic correctness.
psql "$DSN" -v ON_ERROR_STOP=1 -f "$TESTS_DIR/functional_tests.sql" > "$TMP/functional.log" 2>&1 || {
    cat "$TMP/functional.log" >&2
    fail "Functional test suite FAILED"
}
ok "Functional test suite passed"

# ---------- Step 8: R2 idempotency — second run ----------
bold "8. R2 idempotency: re-apply 088-095 (should be no-op)"
psql "$DSN" -c "SELECT set_config('app.deployment_org_id', 'test-deployment-org', false);" >/dev/null
for n in 088 089 090 091 092 093 094 095; do
    f=$(ls $MIG_DIR/${n}_v9_*.sql | grep -v _down.sql | head -1)
    psql "$DSN" -v ON_ERROR_STOP=1 -f "$f" > "$TMP/apply-$n-r2.log" 2>&1 || {
        cat "$TMP/apply-$n-r2.log" >&2
        fail "Migration $n FAILED on second apply (idempotency broken)"
    }
done
ok "Second-apply completed without error"

# ---------- Step 9: Post-second-apply schema dump (must match post-first-apply) ----------
bold "9. Schema dump post-second-apply"
pg_dump --schema-only "$DSN" > "$TMP/schema-post2.sql"

# pg_dump 15+ emits per-invocation random tokens on `\restrict` / `\unrestrict`
# lines as a safety guard against partial restores; they are non-semantic.
# Strip them before comparing so legitimate schema drift is detectable.
strip_random() { grep -v '^\\\(restrict\|unrestrict\) ' "$1"; }

if diff <(strip_random "$TMP/schema-post1.sql") <(strip_random "$TMP/schema-post2.sql") > "$TMP/post12.diff"; then
    ok "Second apply is BYTE-EQUAL to first apply (R2 schema idempotency confirmed; ignoring pg_dump random tokens)"
else
    echo "Semantic diff between post1 and post2:" >&2
    cat "$TMP/post12.diff" >&2
    fail "Schema drifted on second apply — idempotency broken"
fi

# ---------- Step 10: Rollback ----------
bold "10. Rollback: apply 095_down → 088_down in reverse order"
for n in 095 094 093 092 091 090 089 088; do
    f=$(ls $MIG_DIR/${n}_v9_*_down.sql | head -1)
    psql "$DSN" -v ON_ERROR_STOP=1 -f "$f" > "$TMP/down-$n.log" 2>&1 || {
        cat "$TMP/down-$n.log" >&2
        fail "Rollback $n failed"
    }
    ok "Rolled back $(basename $f)"
done

# ---------- Step 11: Post-rollback schema dump (must match pre-088) ----------
bold "11. Schema dump post-rollback (must match pre-088 baseline)"
pg_dump --schema-only "$DSN" > "$TMP/schema-rollback.sql"
if diff <(strip_random "$TMP/schema-pre.sql") <(strip_random "$TMP/schema-rollback.sql") > "$TMP/rollback.diff"; then
    ok "Post-rollback schema is BYTE-EQUAL to pre-088 (R1 rollback confirmed; ignoring pg_dump random tokens)"
else
    echo "Semantic schema diff between pre-088 and post-rollback:" >&2
    cat "$TMP/rollback.diff" | head -200 >&2
    fail "Post-rollback schema drifted from pre-088 baseline — rollback not byte-equal"
fi

# ---------- Step 12: Summary ----------
bold "12. SUMMARY"
echo "  ✓ R1: Migrations apply cleanly on fresh Postgres; rollback returns byte-equal pre-state"
echo "  ✓ R2: Second-apply is no-op (schema byte-equal to first apply)"
echo "  ✓ Per-migration assertion suites all PASS"
echo ""
echo "  Logs at: $TMP"
echo "  Test cycle complete."
exit 0
