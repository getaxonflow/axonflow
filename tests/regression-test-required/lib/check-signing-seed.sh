#!/usr/bin/env bash
# check-signing-seed.sh - run the trusted-key seed guard (#4470).
#
# Builds tests/regression-test-required/lib/signing_seed_guard.go (stdlib
# only, no module) and runs it over the repository's top level. Any argument
# is passed through and wins over the default -root (e.g. the community-mirror
# sync passes `-root <staged tree> -keys-root <enterprise checkout> -walk`).
#
# Callers: .pre-commit-config.yaml (hook licence-signing-seed-guard), the
# "Trusted licence-key seed guard" step of .github/workflows/sync-community-repo.yml,
# and tests/regression-test-required/signing_seed_guard_test.sh.
#
# Exit: 0 clean, 1 a trusted key's seed is in the tree, 2 the guard could not
# run (a missing toolchain is a refusal, never a pass).
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if ! command -v go >/dev/null 2>&1; then
  echo "signing-seed guard: go is not installed, so the guard cannot run; refusing rather than passing unchecked" >&2
  exit 2
fi
root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/signing-seed-guard.XXXXXX")" || exit 2
trap 'rm -rf "$work"' EXIT
# Built from inside the temp dir with GOWORK/GOFLAGS cleared: the file is
# stdlib-only and belongs to no module, and an ambient -tags or go.work must
# not change what is built.
if ! (cd "$work" && GOWORK=off GOFLAGS= go build -o "$work/guard" "$here/signing_seed_guard.go"); then
  echo "signing-seed guard: build failed; refusing" >&2
  exit 2
fi
"$work/guard" -root "$root" "$@"
