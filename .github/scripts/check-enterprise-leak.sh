#!/usr/bin/env bash
# Fail-closed enterprise-leak gate (#3270, hardened #3276).
#
# Scans a staged community-sync directory for any Go file whose build constraint
# selects the ENTERPRISE build (`//go:build enterprise` or the legacy
# `// +build enterprise`) and REFUSES to proceed if one is present. This is the
# permanent enforcement of "no enterprise-only source reaches the public
# community mirror": it is the gap that let the compliance modules (rbi, sebi,
# euaiact, masfeat, ojk, compliancereport) ship publicly for ~3-4 months because
# the sync excluded enterprise code by *_enterprise.go FILENAME while those
# modules carry the tag in normally-named files.
#
# Extracted from sync-community-repo.yml's inline step so it is unit-testable:
# tests/regression-test-required/enterprise_leak_gate_test.sh.
#
# Usage: check-enterprise-leak.sh <staged-dir>
# Exit:  0 = clean (no enterprise-tagged Go source)
#        1 = an enterprise-tagged file is present, OR the scan could not run
#            (fail CLOSED - a scan that cannot complete must never be read as
#            "no enterprise files").
set -uo pipefail

DIR="${1:?usage: check-enterprise-leak.sh <staged-dir>}"

# Fail closed if the target is not a readable directory: a scan that cannot even
# start must not be mistaken for a clean tree.
if [ ! -d "$DIR" ]; then
  echo "ERROR: leak-gate scan target '$DIR' is not a directory - failing CLOSED" >&2
  exit 1
fi

# grep exit codes: 0 = match(es), 1 = no match (clean), >=2 = error. Capture the
# code rather than `|| true`: `|| true` collapses a grep ERROR (exit 2 -
# unreadable tree, IO failure, bad regex) into an empty, "clean" result, so a
# scan that could not COMPLETE would read as "no enterprise files" and the sync
# would proceed. Any exit >1 fails closed. Anchored at start-of-line so a
# doc/comment line that merely mentions "//go:build enterprise" (it begins with
# "// ") is never matched, and neither is the `//go:build !enterprise` negation
# that the community stubs carry.
LEAKED=""
GREP_RC=0
LEAKED=$(grep -rlE '^//go:build enterprise|^// \+build enterprise' "$DIR" --include='*.go') || GREP_RC=$?

if [ "$GREP_RC" -gt 1 ]; then
  echo "ERROR: leak-gate scan did not complete (grep exit ${GREP_RC}) - failing CLOSED, refusing to sync" >&2
  echo "A scan that cannot run must never be read as 'no enterprise-tagged source'." >&2
  exit 1
fi

if [ -n "$LEAKED" ]; then
  echo "ERROR: enterprise-tagged source would leak to the community mirror - blocked" >&2
  echo "" >&2
  echo "The following staged files carry a '//go:build enterprise' (or legacy" >&2
  echo "'// +build enterprise') constraint and must NOT reach getaxonflow/axonflow:" >&2
  echo "$LEAKED" | sed "s|^${DIR%/}/|  - |" >&2
  echo "" >&2
  echo "Fix: exclude each such file from the community copy (it is enterprise-only)," >&2
  echo "and confirm its community counterpart carries the '//go:build !enterprise'" >&2
  echo "stub that the community binary needs." >&2
  exit 1
fi

echo "OK: no enterprise-tagged source in the staged community copy ($DIR)"
