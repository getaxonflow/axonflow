#!/usr/bin/env bash
# Keeps the local, container, and ECS Prometheus surfaces on one image and URL contract.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

dockerfile_image="$(sed -n 's/^FROM \(prom\/prometheus:[^ ]*\).*$/\1/p' "$ROOT/platform/monitoring/Dockerfile" | sed -n '1p')"
script_image="$(sed -n 's/^PROM_IMAGE_DEFAULT="\([^"]*\)"$/\1/p' "$ROOT/scripts/testing/check-monitoring-rules.sh")"
compose_image="$(sed -n '/^[[:space:]]*prometheus:$/,/^[[:space:]]*[a-zA-Z0-9_-]*:$/s/^[[:space:]]*image:[[:space:]]*\(prom\/prometheus:[^[:space:]]*\).*$/\1/p' "$ROOT/docker-compose.yml" | sed -n '1p')"
compose_block="$(sed -n '/^  prometheus:$/,/^  [a-zA-Z0-9_-]*:$/p' "$ROOT/docker-compose.yml")"

[ -n "$dockerfile_image" ]
[ "$dockerfile_image" = "$script_image" ] || {
  echo "Prometheus validator uses $script_image; Dockerfile uses $dockerfile_image" >&2
  exit 1
}
[ "$dockerfile_image" = "$compose_image" ] || {
  echo "docker-compose uses $compose_image; Dockerfile uses $dockerfile_image" >&2
  exit 1
}
grep -Fq -- "'--web.external-url=/prometheus'" <<<"$compose_block" || {
  echo "docker-compose probes /prometheus but does not start Prometheus with --web.external-url=/prometheus" >&2
  exit 1
}

health_url="http://localhost:9090/prometheus/-/healthy"
for rel in \
  Makefile \
  docker-compose.yml \
  platform/monitoring/Dockerfile \
  infrastructure/cloudformation/community-saas-ecs.yaml \
  ee/platform/aws-marketplace/cloudformation-ecs-fargate.yaml
do
  grep -Fq "$health_url" "$ROOT/$rel" || {
    echo "$rel does not use the Prometheus external-url health endpoint $health_url" >&2
    exit 1
  }
done

if rg -n 'http://localhost:9090/-/healthy' "$ROOT" \
  --glob '!**/prometheus_runtime_contract_test.sh'; then
  echo "a Prometheus health check bypasses the configured /prometheus external URL" >&2
  exit 1
fi

printf 'Prometheus runtime contract PASS: %s and /prometheus/-/healthy\n' "$dockerfile_image"
