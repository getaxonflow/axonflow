#!/usr/bin/env bash
# Static release contract for the custom Grafana image. Runtime boot, plugin
# loading, and vulnerability checks are performed by the release train; this
# test prevents the source from silently returning to floating or full images.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DOCKERFILE="${SCRIPT_DIR}/../Dockerfile"

fail() { echo "FAIL: $1"; exit 1; }

grep -Fq 'FROM grafana/grafana:13.3.0-slim@sha256:a66f098dd9b2e1b5a19287ff176db02d895122488c6e39b3dfcd3fb897039225' "${DOCKERFILE}" \
  || fail "Grafana slim base must be versioned and pinned by manifest digest"
grep -Fq 'ARG PROMETHEUS_PLUGIN_VERSION=13.2.4' "${DOCKERFILE}" \
  || fail "Prometheus plugin version is not pinned"
grep -Fq 'ARG POSTGRES_PLUGIN_VERSION=13.0.5' "${DOCKERFILE}" \
  || fail "PostgreSQL plugin version is not pinned"
grep -Fq 'ARG TEMPO_PLUGIN_VERSION=13.3.0' "${DOCKERFILE}" \
  || fail "Tempo plugin version is not pinned"
grep -Fq 'FROM runtime-base AS otel' "${DOCKERFILE}" \
  || fail "Tempo must remain isolated to the optional OTel target"
grep -Fq 'FROM runtime-base AS release' "${DOCKERFILE}" \
  || fail "the Tempo-free production target must remain the default final stage"
grep -Fq 'FROM golang:1.27.3-alpine3.24@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS postgres-plugin-builder' "${DOCKERFILE}" \
  || fail "PostgreSQL plugin builder must be patched and digest-pinned"
grep -Fq 'ARG POSTGRES_PLUGIN_SOURCE_COMMIT=975580aadf51fa075e0181026abd0dcfb9f366dd' "${DOCKERFILE}" \
  || fail "PostgreSQL backend source commit is not pinned"
grep -Fq '10e3b266e2d648f53e30add109f397aa59270fcc541b0ad44e8d5b97d6366b84' "${DOCKERFILE}" \
  || fail "PostgreSQL backend source archive checksum is not pinned"
grep -Fq 'GF_PLUGINS_PREINSTALL_AUTO_UPDATE=false' "${DOCKERFILE}" \
  || fail "runtime plugin auto-update must remain disabled"
grep -Fq 'GF_PLUGINS_PREINSTALL_DISABLED=true' "${DOCKERFILE}" \
  || fail "runtime plugin preinstallation must remain disabled"
grep -Fq 'GF_PLUGINS_PLUGIN_ADMIN_ENABLED=false' "${DOCKERFILE}" \
  || fail "runtime plugin administration must remain disabled"
grep -Fq 'GF_PLUGINS_ALLOW_LOADING_UNSIGNED_PLUGINS=grafana-postgresql-datasource' "${DOCKERFILE}" \
  || fail "the unsigned-plugin exception must remain scoped to PostgreSQL"
grep -Fq 'GF_PLUGIN_CANVAS_AS_EXTERNAL=false' "${DOCKERFILE}" \
  || fail "the slim image must retain Grafana 13's supported core Canvas fallback"
grep -Fq 'chown -R root:root /usr/share/grafana/data/plugins-bundled' "${DOCKERFILE}" \
  || fail "bundled plugins must remain root-owned"
grep -Fq 'chmod -R a-w /usr/share/grafana/data/plugins-bundled' "${DOCKERFILE}" \
  || fail "bundled plugins must remain non-writable at runtime"

for checksum in \
  117edd789f96f4dc6f2e79bef6be3ea10e9ffec775e81e05c16954bcc10cc3a0 \
  c6aaae69fe3e7996d9ce9087bfd6f2b25f8ee540f78b15ee3dc560e6f7c206c2 \
  094c42befc67a484381b78d385bf759b9166f27d27cdcc620503c0964b3ba270 \
  7c1569c906d99b2ad49ef6ab8abe8b0bb3b679577c6f8a72bbc8b06b1460d4f0 \
  692135f83a7430e54dd2aeaf89da7c3f7b7561ea7826582294910d7c59842bd1 \
  0f8dbee754eb6924d17c66b07fc5991b34ef446ffadfb1807f0d4468e0289e51; do
  grep -Fq "${checksum}" "${DOCKERFILE}" || fail "missing release-asset checksum ${checksum}"
done

if grep -Eq '^FROM[[:space:]]+grafana/grafana:(latest|10\.|11\.|12\.|13\.3\.0([^@-]|$))' "${DOCKERFILE}"; then
  fail "Grafana base is floating, non-slim, or from the vulnerable-era release line"
fi

echo "PASS: Grafana base and required data-source plugins are immutable and drift-disabled"
