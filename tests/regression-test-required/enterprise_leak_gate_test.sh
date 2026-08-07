#!/usr/bin/env bash
# Regression guard for the fail-closed enterprise-leak gate
# (.github/scripts/check-enterprise-leak.sh), which blocks any file whose Go
# build constraint selects the ENTERPRISE build from reaching the public
# community mirror.
#
# THE BUG THIS GUARDS
# -------------------
# The community sync excluded enterprise code by *_enterprise.go FILENAME. The
# compliance modules (rbi, sebi, euaiact, masfeat, ojk, compliancereport) carry
# `//go:build enterprise` in normally-named files, so the name-based exclusion
# missed them and their full source shipped to the public mirror for ~3-4
# months (#3270). The gate now excludes by BUILD-TAG CONTENT and fails closed if
# any enterprise-tagged file survives into the staged community copy.
#
# WHAT THIS ASSERTS
#   1. A `//go:build enterprise` file (and the legacy `// +build enterprise`
#      form) in the staged tree is CAUGHT (non-zero exit).
#   2. A clean tree (community `//go:build !enterprise` stubs + plain files +
#      files that merely MENTION the tag mid-line) is ACCEPTED (exit 0).
#   3. A scan that cannot run FAILS CLOSED (exit non-zero) rather than reading as
#      "no enterprise files" - the #3276 hardening. Both a missing target and a
#      grep that errors mid-scan (unreadable subtree) are covered.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
GATE="$REPO_ROOT/.github/scripts/check-enterprise-leak.sh"
FAIL=0

if [ ! -x "$GATE" ]; then
  echo "❌ gate script missing or not executable: $GATE"
  exit 1
fi

TMP="$(mktemp -d)"
trap 'chmod -R u+rwx "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT

# 1. CLEAN tree -> exit 0
mkdir -p "$TMP/clean/pkg"
printf '//go:build !enterprise\n\npackage pkg\n' > "$TMP/clean/pkg/thing_community.go"
printf 'package pkg\n\nfunc F() {}\n' > "$TMP/clean/pkg/plain.go"
printf 'package pkg\n// see //go:build enterprise for the ee variant\n' > "$TMP/clean/pkg/doc.go"
if "$GATE" "$TMP/clean" >/dev/null 2>&1; then
  echo "✅ PASS: clean tree accepted (community stub + plain + mid-line mention)"
else
  echo "❌ FAIL: clean tree rejected (exit $?)"; FAIL=1
fi

# 2. LEAK: an enterprise-tagged file -> non-zero
mkdir -p "$TMP/leak/pkg"
printf '//go:build enterprise\n\npackage pkg\n' > "$TMP/leak/pkg/impl.go"
if "$GATE" "$TMP/leak" >/dev/null 2>&1; then
  echo "❌ FAIL: //go:build enterprise file NOT caught (fail-OPEN)"; FAIL=1
else
  echo "✅ PASS: //go:build enterprise file caught"
fi

# 2b. legacy `// +build enterprise` form -> non-zero
mkdir -p "$TMP/leak_legacy/pkg"
printf '// +build enterprise\n\npackage pkg\n' > "$TMP/leak_legacy/pkg/impl.go"
if "$GATE" "$TMP/leak_legacy" >/dev/null 2>&1; then
  echo "❌ FAIL: legacy '// +build enterprise' NOT caught (fail-OPEN)"; FAIL=1
else
  echo "✅ PASS: legacy '// +build enterprise' caught"
fi

# 3. FAIL-CLOSED: a scan target that does not exist -> non-zero
if "$GATE" "$TMP/does-not-exist" >/dev/null 2>&1; then
  echo "❌ FAIL: missing scan target read as clean (fail-OPEN)"; FAIL=1
else
  echo "✅ PASS: missing scan target fails closed"
fi

# 3b. FAIL-CLOSED: grep errors mid-scan (unreadable subtree) -> non-zero.
# root ignores file permissions, so this specific case is only meaningful for a
# non-root runner; skip it under root rather than assert a guarantee that does
# not hold there.
if [ "$(id -u)" != "0" ]; then
  mkdir -p "$TMP/unreadable/pkg"
  printf 'package pkg\n' > "$TMP/unreadable/pkg/x.go"
  chmod 000 "$TMP/unreadable/pkg"
  if "$GATE" "$TMP/unreadable" >/dev/null 2>&1; then
    echo "❌ FAIL: unreadable subtree (grep error) read as clean (fail-OPEN)"; FAIL=1
  else
    echo "✅ PASS: unreadable subtree (grep error) fails closed"
  fi
  chmod 755 "$TMP/unreadable/pkg"
else
  echo "ℹ️  SKIP: grep-error fail-closed case (running as root, which ignores file permissions)"
fi

if [ "$FAIL" = "0" ]; then
  echo "✅ enterprise_leak_gate_test PASSED"
else
  echo "❌ enterprise_leak_gate_test FAILED"
  exit 1
fi
