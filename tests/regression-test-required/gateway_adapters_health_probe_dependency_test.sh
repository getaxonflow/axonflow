#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
DOCKERFILE="$ROOT/platform/gateway-adapters/cmd/axonflow-gateway-adapters/Dockerfile"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

test -f "$DOCKERFILE" || fail "gateway-adapters Dockerfile is missing"

grep -Fq 'go get github.com/grpc-ecosystem/grpc-health-probe@v0.4.53' "$DOCKERFILE" \
  || fail "grpc_health_probe source version is not pinned"
grep -Fq 'go get github.com/go-jose/go-jose/v4@v4.1.6' "$DOCKERFILE" \
  || fail "grpc_health_probe build does not override Go JOSE to the remediated version"

if grep -Eq 'github\.com/go-jose/go-jose/v4@v4\.1\.[0-5]([^0-9]|$)' "$DOCKERFILE"; then
  fail "gateway-adapters image still pins a vulnerable Go JOSE version"
fi

echo "PASS: gateway-adapters health probe pins remediated Go JOSE v4.1.6"
