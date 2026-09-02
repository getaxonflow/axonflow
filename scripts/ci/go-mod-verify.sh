#!/usr/bin/env bash
# `go mod verify` that tolerates filesystem-replaced modules, and nothing else.
#
# WHY THIS EXISTS.
#
# `go mod verify` checks each DOWNLOADED module zip in the module cache against
# go.sum. A module replaced by a filesystem path has no zip to check, so Go
# reports
#
#   <module> <version>: missing ziphash: open hash: no such file or directory
#
# and exits 1. That is not a tampering signal; there is nothing to tamper with.
#
# The repository already met this: `ee/` and `ee/platform/customer-portal` both
# carry local replaces and both fail `go mod verify` on main, which is why
# test.yml skips the step for them outright ("go mod verify skipped for ee/
# because it has a replace directive"). `platform/` had no local replace and so
# still ran the check — until it gained one (`platform/decision`, #3603).
#
# Skipping the step for `platform/` too would have been the consistent move, and
# it is the wrong one: it drops the check for the ~200 modules that ARE
# downloaded in order to accommodate one that is not. `go mod verify` does not
# stop at the first failure — it verifies every module in the build list and
# reports each bad one — so the failures can be filtered instead of the check
# being abandoned.
#
# WHAT IS TOLERATED, EXACTLY.
#
# Only a "missing ziphash" line naming a module that Go ITSELF reports as
# replaced by a filesystem path. The allow-list is computed from `go list -m`,
# not from a string pattern, so a real dependency that somehow produced this
# message would still fail: the module has to actually be filesystem-replaced to
# be excused. Every other line, and any other kind of verification failure,
# fails the step.
#
# Usage: run from the module directory.
#
#   bash "$REPO_ROOT/scripts/ci/go-mod-verify.sh"

set -uo pipefail

log="$(mktemp)"
trap 'rm -f "$log" "$log.replaced"' EXIT

# GO_MOD_VERIFY_CMD is a TEST SEAM. A filter that cannot be shown to fail is a
# rubber stamp, and the failing branch here is the one that never runs in
# practice - by construction, since a clean tree never produces an unexpected
# line. The seam lets the self-test plant one.
GO_MOD_VERIFY_CMD="${GO_MOD_VERIFY_CMD:-go mod verify}"

if $GO_MOD_VERIFY_CMD >"$log" 2>&1; then
    cat "$log"
    exit 0
fi

# Modules replaced by a FILESYSTEM path: a replacement with no version is a
# directory replacement. A version-bearing replacement is still downloaded and
# must still verify, so it is deliberately not excused.
go list -m -f '{{if .Replace}}{{if not .Replace.Version}}{{.Path}}{{end}}{{end}}' all \
    2>/dev/null | grep -v '^$' | sort -u >"$log.replaced" || true

if [ ! -s "$log.replaced" ]; then
    echo "go mod verify failed and this module has no filesystem-replaced dependencies:"
    cat "$log"
    exit 1
fi

# A failure that produced NO OUTPUT is a failure, not a pass. `go mod verify`
# exiting non-zero having written nothing means it died before reporting -- an
# OOM kill, a signal, exit 137 -- and the loop below would then classify zero
# lines, leave `unexpected` at 0, and print "all modules verified". That is the
# vacuous-scope failure this directory's own self-test calls "the one that
# actually happens in practice".
if [ ! -s "$log" ]; then
    echo "go mod verify failed and produced no output (exit was non-zero); refusing to report success."
    exit 1
fi

unexpected=0
# `|| [ -n "$line" ]` so a final line with no trailing newline is still
# classified. Without it `read` returns non-zero at EOF and the last line is
# dropped -- and the last line is exactly where a real failure can hide behind
# an excused one.
while IFS= read -r line || [ -n "$line" ]; do
    [ -z "$line" ] && continue
    # A tolerable line is exactly: "<module> <version>: missing ziphash: ..."
    # for a module on the filesystem-replaced list.
    if printf '%s' "$line" | grep -q 'missing ziphash'; then
        mod="${line%% *}"
        if grep -qxF "$mod" "$log.replaced"; then
            echo "  (skipped, replaced by a local path: $mod)"
            continue
        fi
    fi
    echo "UNEXPECTED: $line"
    unexpected=1
done <"$log"

if [ "$unexpected" -ne 0 ]; then
    echo ""
    echo "go mod verify reported a failure that is not a filesystem-replaced module."
    exit 1
fi

echo "all downloaded modules verified (filesystem-replaced modules have no zip to verify)"
