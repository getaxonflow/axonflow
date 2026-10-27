# AxonFlow Grafana
# Custom Grafana with auto-provisioned dashboards and dynamic datasource configuration.
#
# The official slim image intentionally excludes bundled data-source plugins. We
# install only the two production data sources AxonFlow uses, from
# checksum-pinned upstream release artifacts. An opt-in `otel` build target adds
# Tempo for the local OTel overlay without expanding the production image.

FROM golang:1.27.3-alpine3.24@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS postgres-plugin-builder

ARG TARGETOS
ARG TARGETARCH
ARG POSTGRES_PLUGIN_SOURCE_COMMIT=975580aadf51fa075e0181026abd0dcfb9f366dd

WORKDIR /src

# v13.0.5 predates Go 1.27.3 and x/net 0.61.0. Grafana's signed upstream
# dependency-only commit updates those vulnerable build inputs; build the
# backend from that immutable source while retaining the v13.0.5 release's
# frontend and plugin metadata below. Replacing the binary necessarily
# invalidates the release manifest, which is removed in the runtime stage.
ADD --checksum=sha256:10e3b266e2d648f53e30add109f397aa59270fcc541b0ad44e8d5b97d6366b84 \
  https://codeload.github.com/grafana/grafana-postgresql-datasource/tar.gz/975580aadf51fa075e0181026abd0dcfb9f366dd \
  /tmp/postgres-plugin-source.tar.gz

RUN set -eux; \
    tar -xzf /tmp/postgres-plugin-source.tar.gz --strip-components=1; \
    test "${POSTGRES_PLUGIN_SOURCE_COMMIT}" = "975580aadf51fa075e0181026abd0dcfb9f366dd"; \
    CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
      go build -trimpath -buildvcs=false \
      -o "/out/gpx_grafana_postgresql_datasource_linux_${TARGETARCH}" ./pkg

FROM grafana/grafana:13.3.0-slim@sha256:a66f098dd9b2e1b5a19287ff176db02d895122488c6e39b3dfcd3fb897039225 AS runtime-base

ARG TARGETARCH
ARG PROMETHEUS_PLUGIN_VERSION=13.2.4
ARG POSTGRES_PLUGIN_VERSION=13.0.5

# Do not install or replace plugins at container startup, and do not expose the
# UI plugin installer. Upgrades belong in a reviewed image build with fresh
# checksums and dual-arch scans. The PostgreSQL plugin is the only narrowly
# allowed unsigned ID: its upstream signed release manifest cannot describe
# the dependency-fixed backend rebuilt above. The plugin tree is root-owned and
# non-writable by Grafana, and the whole OCI image is digest-pinned at deploy.
ENV GF_PLUGINS_PREINSTALL_DISABLED=true \
    GF_PLUGINS_PREINSTALL_AUTO_UPDATE=false \
    GF_PLUGINS_PLUGIN_ADMIN_ENABLED=false \
    GF_PLUGINS_ALLOW_LOADING_UNSIGNED_PLUGINS=grafana-postgresql-datasource \
    GF_PLUGIN_CANVAS_AS_EXTERNAL=false

USER root

RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) \
        prometheus_sha="117edd789f96f4dc6f2e79bef6be3ea10e9ffec775e81e05c16954bcc10cc3a0"; \
        postgres_sha="094c42befc67a484381b78d385bf759b9166f27d27cdcc620503c0964b3ba270" \
        ;; \
      arm64) \
        prometheus_sha="c6aaae69fe3e7996d9ce9087bfd6f2b25f8ee540f78b15ee3dc560e6f7c206c2"; \
        postgres_sha="7c1569c906d99b2ad49ef6ab8abe8b0bb3b679577c6f8a72bbc8b06b1460d4f0" \
        ;; \
      *) \
        echo "unsupported release architecture: ${TARGETARCH}" >&2; \
        exit 1 \
        ;; \
    esac; \
    prometheus_archive="/tmp/prometheus.zip"; \
    postgres_archive="/tmp/postgres.zip"; \
    wget -q -O "${prometheus_archive}" \
      "https://github.com/grafana/grafana-prometheus-datasource/releases/download/v${PROMETHEUS_PLUGIN_VERSION}/prometheus-${PROMETHEUS_PLUGIN_VERSION}.linux_${TARGETARCH}.zip"; \
    wget -q -O "${postgres_archive}" \
      "https://github.com/grafana/grafana-postgresql-datasource/releases/download/v${POSTGRES_PLUGIN_VERSION}/grafana-postgresql-datasource-${POSTGRES_PLUGIN_VERSION}.linux_${TARGETARCH}.zip"; \
    echo "${prometheus_sha}  ${prometheus_archive}" | sha256sum -c -; \
    echo "${postgres_sha}  ${postgres_archive}" | sha256sum -c -; \
    unzip -q "${prometheus_archive}" -d /usr/share/grafana/data/plugins-bundled; \
    unzip -q "${postgres_archive}" -d /usr/share/grafana/data/plugins-bundled; \
    test -x "/usr/share/grafana/data/plugins-bundled/prometheus/gpx_grafana-prometheus-datasource_linux_${TARGETARCH}"; \
    test -x "/usr/share/grafana/data/plugins-bundled/grafana-postgresql-datasource/gpx_grafana_postgresql_datasource_linux_${TARGETARCH}"; \
    rm -f /usr/share/grafana/data/plugins-bundled/grafana-postgresql-datasource/MANIFEST.txt; \
    chown -R root:root /usr/share/grafana/data/plugins-bundled; \
    chmod -R a-w /usr/share/grafana/data/plugins-bundled; \
    rm -f "${prometheus_archive}" "${postgres_archive}"

# Replace the release backend (built with vulnerable Go/x-net versions) with
# the binary built above from Grafana's signed dependency-fix commit.
COPY --from=postgres-plugin-builder --chown=root:root --chmod=0555 /out/ \
  /usr/share/grafana/data/plugins-bundled/grafana-postgresql-datasource/

COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Copy dashboard provisioning config (static - just points to dashboard directory)
COPY provisioning/dashboards/dashboards.yaml /etc/grafana/provisioning/dashboards/dashboards.yaml

# Copy dashboards (baked into image for immediate availability)
COPY dashboards/*.json /var/lib/grafana/dashboards/

USER grafana

ENTRYPOINT ["/docker-entrypoint.sh"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q --spider http://localhost:3000/api/health || exit 1

# The official /run.sh handles Grafana startup after datasource generation.
CMD []

# Local-only OTel overlay target. The v13.3.0 Tempo release binary embeds
# Tempo commit bcfe9f230c1de0f79cfd2110b38062e0f41c81e9, which is a verified
# descendant of both CVE fix commits 650eb198 and bb8ca663. Trivy 0.72 reports
# those CVEs because the dependency uses a v1 pseudo-version even though its
# source commit contains both fixes. Keep this plugin out of the production
# target until upstream publishes metadata scanners can classify correctly.
FROM runtime-base AS otel

ARG TARGETARCH
ARG TEMPO_PLUGIN_VERSION=13.3.0

USER root

RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) tempo_sha="692135f83a7430e54dd2aeaf89da7c3f7b7561ea7826582294910d7c59842bd1" ;; \
      arm64) tempo_sha="0f8dbee754eb6924d17c66b07fc5991b34ef446ffadfb1807f0d4468e0289e51" ;; \
      *) echo "unsupported OTel architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    tempo_archive="/tmp/tempo.zip"; \
    wget -q -O "${tempo_archive}" \
      "https://github.com/grafana/grafana-tempo-datasource/releases/download/v${TEMPO_PLUGIN_VERSION}/tempo-${TEMPO_PLUGIN_VERSION}.linux_${TARGETARCH}.zip"; \
    echo "${tempo_sha}  ${tempo_archive}" | sha256sum -c -; \
    unzip -q "${tempo_archive}" -d /usr/share/grafana/data/plugins-bundled; \
    test -x "/usr/share/grafana/data/plugins-bundled/tempo/gpx_grafana-tempo-datasource_linux_${TARGETARCH}"; \
    chown -R root:root /usr/share/grafana/data/plugins-bundled/tempo; \
    chmod -R a-w /usr/share/grafana/data/plugins-bundled/tempo; \
    rm -f "${tempo_archive}"

USER grafana

# Keep the production/release image as the Dockerfile's default final target.
FROM runtime-base AS release
