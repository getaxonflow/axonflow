#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
DOCKERFILE="${MINIO_DOCKERFILE:-$ROOT/minio/Dockerfile}"

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
  'github.com/go-jose/go-jose/v4@v4.1.6' \
  'github.com/klauspost/compress@v1.19.0' \
  'github.com/prometheus/prometheus@v0.311.3' \
  'github.com/rabbitmq/amqp091-go@v1.13.0' \
  'go.opentelemetry.io/otel/sdk@v1.44.0' \
  'golang.org/x/crypto@v0.58.0' \
  'golang.org/x/net@v0.62.0' \
  'golang.org/x/text@v0.43.0' \
  'google.golang.org/grpc@v1.83.2'; do
  grep -Fq "$hardened_module" "$DOCKERFILE" \
    || fail "the source build does not pin hardened module $hardened_module"
done

# MinIO and MC are independent Go module graphs and produce separate binaries.
# A pin in one graph cannot excuse its absence from the other: otherwise one
# binary can silently regain a vulnerability while this contract still sees
# the fixed version elsewhere in the Dockerfile.
minio_graph=$(awk '
  $0 == "WORKDIR /src/minio" { capture = 1; next }
  capture && $0 == "WORKDIR /src/mc" { exit }
  capture { print }
' "$DOCKERFILE")
mc_graph=$(awk '
  $0 == "WORKDIR /src/mc" { capture = 1; next }
  capture && /^FROM[[:space:]]/ { exit }
  capture { print }
' "$DOCKERFILE")

test -n "$minio_graph" || fail "the MinIO build graph could not be extracted"
test -n "$mc_graph" || fail "the MC build graph could not be extracted"
for graph_name in minio mc; do
  case "$graph_name" in
    minio) graph=$minio_graph ;;
    mc) graph=$mc_graph ;;
  esac
  for shared_pin in \
    'github.com/klauspost/compress@v1.19.0' \
    'github.com/prometheus/prometheus@v0.311.3' \
    'golang.org/x/crypto@v0.58.0' \
    'golang.org/x/net@v0.62.0' \
    'golang.org/x/text@v0.43.0' \
    'google.golang.org/grpc@v1.83.2'; do
    grep -Fq "$shared_pin" <<<"$graph" \
      || fail "the $graph_name source graph does not pin hardened module $shared_pin"
  done
done

grep -Eq '^USER[[:space:]]+minio$' "$DOCKERFILE" \
  || fail "the runtime image does not drop root privileges"
grep -Fq 'ENTRYPOINT ["minio"]' "$DOCKERFILE" \
  || fail "the runtime image does not preserve the upstream minio entrypoint contract"

echo "PASS: MinIO is built from checksum-pinned hardened upstream source, includes both licence notices, and runs non-root"
