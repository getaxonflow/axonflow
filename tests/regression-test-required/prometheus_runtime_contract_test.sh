#!/usr/bin/env bash
# Keeps the local, container, and ECS Prometheus surfaces on one upstream release and URL contract.
#
# platform/monitoring/Dockerfile compiles Prometheus from a pinned upstream
# source commit (see prometheus_source_image_contract_test.sh for that build's
# own contract). The three surfaces that must agree on WHICH Prometheus:
#   - the Dockerfile's PROMETHEUS_VERSION (what ships),
#   - docker-compose.yml's prom/prometheus tag (the dev stack; it cannot build
#     the Dockerfile because the Community mirror excludes platform/monitoring/),
#   - scripts/testing/check-monitoring-rules.sh, which must run promtool from a
#     build of the Dockerfile's `upstream` stage and pin no registry tag of its
#     own, so the promtool that validates the rules is the Prometheus that loads
#     them.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DOCKERFILE="$ROOT/platform/monitoring/Dockerfile"
RULES_SCRIPT="$ROOT/scripts/testing/check-monitoring-rules.sh"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

dockerfile_version="$(sed -n 's/^ARG PROMETHEUS_VERSION=\([^ ]*\)$/\1/p' "$DOCKERFILE" | sed -n '1p')"
dockerfile_commit="$(sed -n 's/^ARG PROMETHEUS_COMMIT=\([0-9a-f]\{40\}\)$/\1/p' "$DOCKERFILE" | sed -n '1p')"
compose_image="$(sed -n '/^[[:space:]]*prometheus:$/,/^[[:space:]]*[a-zA-Z0-9_-]*:$/s/^[[:space:]]*image:[[:space:]]*\(prom\/prometheus:[^[:space:]]*\).*$/\1/p' "$ROOT/docker-compose.yml" | sed -n '1p')"
compose_block="$(sed -n '/^  prometheus:$/,/^  [a-zA-Z0-9_-]*:$/p' "$ROOT/docker-compose.yml")"

[ -n "$dockerfile_version" ] || fail "the Dockerfile does not pin ARG PROMETHEUS_VERSION"
[ -n "$dockerfile_commit" ] || fail "the Dockerfile does not pin ARG PROMETHEUS_COMMIT to a 40-hex commit"
if grep -Eq '^FROM[[:space:]]+(--platform=[^[:space:]]+[[:space:]]+)?prom/prometheus' "$DOCKERFILE"; then
  fail "the Dockerfile is FROM a prom/prometheus registry tag; the image is built from source"
fi

[ -n "$compose_image" ] || fail "docker-compose.yml's prometheus service has no prom/prometheus image"
[ "$compose_image" = "prom/prometheus:v${dockerfile_version}" ] || {
  fail "docker-compose uses $compose_image; the Dockerfile builds Prometheus ${dockerfile_version} (expected prom/prometheus:v${dockerfile_version})"
}
grep -Fq -- "'--web.external-url=/prometheus'" <<<"$compose_block" || {
  fail "docker-compose probes /prometheus but does not start Prometheus with --web.external-url=/prometheus"
}

# The rules validator: reads the version from the Dockerfile, builds the
# upstream stage of THAT Dockerfile, and carries no registry pin of its own.
grep -Fq "sed -n 's/^ARG PROMETHEUS_VERSION=" "$RULES_SCRIPT" \
  || fail "check-monitoring-rules.sh does not read PROMETHEUS_VERSION from the Dockerfile"
grep -Eq 'docker build -q --target upstream -t "\$PROM_IMAGE" "\$\{REPO_ROOT\}/platform/monitoring"' "$RULES_SCRIPT" \
  || fail "check-monitoring-rules.sh does not build promtool from the Dockerfile's upstream stage"
if grep -Eq '^[^#]*prom/prometheus:' "$RULES_SCRIPT"; then
  fail "check-monitoring-rules.sh pins a prom/prometheus registry tag; promtool must come from the source build"
fi
grep -Eq '^FROM .* AS upstream$' "$DOCKERFILE" \
  || fail "the Dockerfile has no 'upstream' stage for check-monitoring-rules.sh to build"

health_url="http://localhost:9090/prometheus/-/healthy"
for rel in \
  Makefile \
  docker-compose.yml \
  platform/monitoring/Dockerfile \
  infrastructure/cloudformation/community-saas-ecs.yaml \
  ee/platform/aws-marketplace/cloudformation-ecs-fargate.yaml
do
  grep -Fq "$health_url" "$ROOT/$rel" || {
    fail "$rel does not use the Prometheus external-url health endpoint $health_url"
  }
done

# grep -r rather than rg: on a machine without rg, `if rg ...` reads the
# command-not-found exit as "no match" and this assertion passes vacuously.
if grep -rn 'http://localhost:9090/-/healthy' "$ROOT" \
  --exclude-dir=.git --exclude-dir=node_modules \
  --exclude=prometheus_runtime_contract_test.sh; then
  fail "a Prometheus health check bypasses the configured /prometheus external URL"
fi

printf 'Prometheus runtime contract PASS: Prometheus %s (%s) from source, dev stack %s, promtool from the upstream stage, /prometheus/-/healthy\n' \
  "$dockerfile_version" "${dockerfile_commit:0:12}" "$compose_image"
