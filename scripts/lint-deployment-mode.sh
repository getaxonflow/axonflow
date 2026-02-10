#!/usr/bin/env bash
# lint-deployment-mode.sh — Enforce isCommunityMode() pattern (Issue #1133)
#
# Flags any direct os.Getenv("DEPLOYMENT_MODE") calls outside of allowed files.
# The canonical way to check community mode is via isCommunityMode() in run.go.
# Files that legitimately need the full mode string (not just the boolean) are allowlisted.

set -euo pipefail

# Files that legitimately need raw DEPLOYMENT_MODE access:
# - run.go: defines the canonical isCommunityMode() helper
# - migration_helpers.go: needs full mode string for migration path selection
# - admin_auth.go: needs full mode string for auth matrix (saas, in-vpc-*, community)
# - deployment.go: needs full mode string for deployment config (invpc, saas, default)
ALLOWED_FILES=(
  "platform/agent/run.go"
  "platform/orchestrator/run.go"
  "platform/shared/policy/dynamic_evaluator.go"
  "platform/shared/execution/event_hub.go"
  "platform/agent/migration_helpers.go"
  "ee/platform/customer-portal/middleware/admin_auth.go"
  "ee/platform/customer-portal/config/deployment.go"
)

# Build grep -v exclusion pattern for allowed files.
# Note: --exclude with path separators only works on BSD grep (macOS).
# GNU grep (Linux/CI) matches --exclude against basenames only.
# Using grep -v post-filter ensures cross-platform correctness.
EXCLUDE_PATTERN=""
for f in "${ALLOWED_FILES[@]}"; do
  EXCLUDE_PATTERN="${EXCLUDE_PATTERN:+$EXCLUDE_PATTERN|}^${f}:"
done

# Find violations in non-test Go files
# Note: This catches the canonical form os.Getenv("DEPLOYMENT_MODE").
# It does NOT catch backtick strings (`DEPLOYMENT_MODE`) or indirect access.
VIOLATIONS=$(grep -rn 'os\.Getenv("DEPLOYMENT_MODE")' \
  --include="*.go" \
  --exclude="*_test.go" \
  --exclude="*_integration_test.go" \
  platform/ ee/ 2>/dev/null | \
  grep -Ev "$EXCLUDE_PATTERN" || true)

if [ -n "$VIOLATIONS" ]; then
  echo "❌ DEPLOYMENT_MODE lint check failed (Issue #1133)"
  echo ""
  echo "Found direct os.Getenv(\"DEPLOYMENT_MODE\") calls outside allowed files:"
  echo ""
  echo "$VIOLATIONS"
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "HOW TO FIX:"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
  echo "Use the canonical isCommunityMode() helper instead of raw os.Getenv:"
  echo ""
  echo "  // ✅ Correct"
  echo "  if isCommunityMode() {"
  echo "      return nil"
  echo "  }"
  echo ""
  echo "  // ❌ Wrong — bypasses the canonical pattern"
  echo "  if os.Getenv(\"DEPLOYMENT_MODE\") == \"community\" {"
  echo "      return nil"
  echo "  }"
  echo ""
  echo "If you genuinely need the full mode string (not just the boolean),"
  echo "add your file to the allowlist in scripts/lint-deployment-mode.sh"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  exit 1
fi

echo "✅ DEPLOYMENT_MODE lint check passed — all non-test code uses isCommunityMode()"
