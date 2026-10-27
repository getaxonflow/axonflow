#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
DOCKERFILE="$ROOT/minio/Dockerfile"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

test -f "$DOCKERFILE" || fail "minio/Dockerfile is missing"

grep -Fq 'MINIO_COMMIT=9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a' "$DOCKERFILE" \
  || fail "the MinIO server source commit is not pinned"
grep -Fq 'MC_COMMIT=7394ce0dd2a80935aded936b09fa12cbb3cb8096' "$DOCKERFILE" \
  || fail "the MinIO client source commit is not pinned"

checksum_count="$(grep -c -- '--checksum=sha256:' "$DOCKERFILE")"
test "$checksum_count" -eq 2 \
  || fail "expected two checksum-pinned upstream source archives, found $checksum_count"

compose_files=(docker-compose.yml)
if test -f "$ROOT/docker-compose.enterprise.yml"; then
  compose_files+=(docker-compose.enterprise.yml)
fi

for compose in "${compose_files[@]}"; do
  grep -Fq 'image: axonflow-minio:local' "$ROOT/$compose" \
    || fail "$compose does not use the source-built MinIO image"
  grep -Fq 'dockerfile: minio/Dockerfile' "$ROOT/$compose" \
    || fail "$compose does not build minio/Dockerfile"
  if grep -Eq 'quay\.io/minio/|(^|[[:space:]])minio/(minio|mc):' "$ROOT/$compose"; then
    fail "$compose still depends on a withdrawn upstream container repository"
  fi
done

grep -Fq 'mc anonymous set none local/axonflow-test-bucket' "$ROOT/docker-compose.yml" \
  || fail "the Community test bucket is not explicitly private"
if test -f "$ROOT/docker-compose.enterprise.yml"; then
  grep -Fq 'mc anonymous set none local/axonflow-audit-exports' "$ROOT/docker-compose.enterprise.yml" \
    || fail "the Enterprise audit-export bucket is not explicitly private"
fi

grep -Fq 'COPY --from=builder /out/licenses/minio/ /licenses/minio/' "$DOCKERFILE" \
  || fail "the MinIO server licence is not copied into the runtime image"
grep -Fq 'COPY --from=builder /out/licenses/mc/ /licenses/mc/' "$DOCKERFILE" \
  || fail "the MinIO client licence is not copied into the runtime image"

for hardened_module in \
  'github.com/apache/thrift@v0.24.0' \
  'github.com/buger/jsonparser@v1.1.2' \
  'github.com/go-jose/go-jose/v4@v4.1.4' \
  'github.com/klauspost/compress@v1.19.0' \
  'github.com/prometheus/prometheus@v0.311.3' \
  'github.com/rabbitmq/amqp091-go@v1.13.0' \
  'go.opentelemetry.io/otel/sdk@v1.44.0' \
  'golang.org/x/crypto@v0.57.0' \
  'golang.org/x/net@v0.60.0' \
  'golang.org/x/text@v0.42.0' \
  'google.golang.org/grpc@v1.83.2'; do
  grep -Fq "$hardened_module" "$DOCKERFILE" \
    || fail "the source build does not pin hardened module $hardened_module"
done

grep -Eq '^USER[[:space:]]+minio$' "$DOCKERFILE" \
  || fail "the runtime image does not drop root privileges"
grep -Fq 'ENTRYPOINT ["minio"]' "$DOCKERFILE" \
  || fail "the runtime image does not preserve the upstream minio entrypoint contract"

echo "PASS: MinIO is built from checksum-pinned hardened upstream source, includes both licence notices, and runs non-root"
