#!/usr/bin/env bash
# migrations_internal_not_synced_test.sh — #3168 / #3181
#
# `migrations/internal/` holds AxonFlow's OWN E2E fixtures and demo-tenant
# mappings: the `e2e-test-saas` policy seeds, the `travel-us` /
# `ecommerce-prod-us` `customers` rows carrying `demo@getaxonflow.com`, and a
# README that documents our `production-us` org→tenant mapping and the internal
# seeding workflow.
#
# `.github/workflows/sync-community-repo.yml` rsyncs the repository to the
# PUBLIC community mirror. It excludes `migrations/enterprise/`,
# `migrations/industry/` and `migrations/community-saas/` by name. The #3168
# relocation moved two files OUT of an excluded directory — so without a
# matching exclusion the fix would publish, to a public repository, data that
# had previously only ever reached customer databases.
#
# That is the shape this test exists for: an exclusion list keyed on directory
# names silently stops covering a file the moment the file moves. Every
# never-selected migration category must be excluded from the sync.
#
# Run: bash tests/regression-test-required/migrations_internal_not_synced_test.sh

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SYNC_WORKFLOW="$REPO_ROOT/.github/workflows/sync-community-repo.yml"
HELPERS="$REPO_ROOT/platform/agent/migration_helpers.go"

PASS=0
FAIL=0
ok()   { echo "  ✅ PASS: $1"; PASS=$((PASS + 1)); }
bad()  { echo "  ❌ FAIL: $1"; FAIL=$((FAIL + 1)); }

echo "=== migrations/internal/ must not reach the public community mirror ==="

if [ ! -f "$SYNC_WORKFLOW" ]; then
  echo "  ❌ FAIL: $SYNC_WORKFLOW not found — this test cannot vacuously pass"
  exit 1
fi
if [ ! -f "$HELPERS" ]; then
  echo "  ❌ FAIL: $HELPERS not found — this test cannot vacuously pass"
  exit 1
fi

# Anti-vacuity: the exclusions this test relies on reading must actually be
# there in the shape it greps for. If the workflow stops using `--exclude=` the
# grep below would report "no violation" for the wrong reason.
if ! grep -q -- "--exclude='migrations/enterprise/'" "$SYNC_WORKFLOW"; then
  echo "  ❌ FAIL: the sync workflow no longer carries --exclude='migrations/enterprise/' —"
  echo "          the rsync rule format changed and this test's grep is no longer meaningful."
  exit 1
fi
ok "the sync workflow still expresses exclusions as --exclude='<dir>/' (anti-vacuity check)"

# The categories no deployment mode selects, read from the Go source rather
# than hard-coded, so adding one to neverSelectedMigrationCategories without
# excluding it from the sync fails here.
CATEGORIES="$(sed -n 's/^var neverSelectedMigrationCategories = \[\]string{\(.*\)}$/\1/p' "$HELPERS" \
  | tr -d '"' | tr ',' '\n' | tr -d '[:space:]' | grep -v '^$')"

if [ -z "$CATEGORIES" ]; then
  echo "  ❌ FAIL: could not parse neverSelectedMigrationCategories out of $HELPERS."
  echo "          The declaration moved or changed shape; this test would otherwise"
  echo "          check nothing and report success."
  exit 1
fi

for cat in $CATEGORIES; do
  if grep -q -- "--exclude='migrations/${cat}/'" "$SYNC_WORKFLOW"; then
    ok "migrations/${cat}/ is excluded from the community sync"
  else
    bad "migrations/${cat}/ is NOT excluded from the community sync — its contents would be published"
  fi

  if [ -d "$REPO_ROOT/migrations/${cat}" ]; then
    ok "migrations/${cat}/ exists on disk (the exclusion is not decorative)"
  else
    bad "migrations/${cat}/ is declared never-selected but has no directory — one of the two is wrong"
  fi
done

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "All tests passed!"
