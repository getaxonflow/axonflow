# syntax=docker/dockerfile:1.7

# AxonFlow Grafana
# Custom Grafana with auto-provisioned dashboards and dynamic datasource configuration.
#
# The official slim image intentionally excludes bundled data-source plugins. We
# install only the two production data sources AxonFlow uses, from
# checksum-pinned upstream release artifacts. An opt-in `otel` build target adds
# Tempo for the local OTel overlay without expanding the production image.
#
# BOTH DATA-SOURCE BACKENDS ARE REBUILT FROM PINNED SOURCE (2026-11, #4486).
# Every published release of the Prometheus and PostgreSQL data-source plugins
# embeds golang.org/x/net below v0.62.0 and carries HIGH CVE-2026-78661; the
# release pipeline scans at HIGH,CRITICAL with exit-code 1 and no ignore list,
# so cohort 2e36c876 stopped on this image. The release zips still supply the
# frontend and plugin metadata; the Go backend inside each is replaced by one
# compiled here from the plugin's immutable source commit with x/net moved to
# the floor first (the same approach as platform/monitoring/Dockerfile and
# minio/Dockerfile). Replacing a backend invalidates the plugin's signed
# MANIFEST, which is removed, and the plugin id is allowed as unsigned. The
# build then PROVES the floor: `go version -m` on the Grafana server binary and
# on both rebuilt backends, and the build fails if any one is below it.

# Upstream Grafana, digest-pinned. 13.3.1 is the first 13.3 release whose own
# server binary embeds x/net v0.62.0 (13.3.0 embedded v0.61.0).
FROM grafana/grafana:13.3.1-slim@sha256:49221b454a407632e47e6d4bbc2bb1585c462bf68c6fb9ebed4aa072b027595a AS grafana-upstream

FROM golang:1.27.3-alpine3.24@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS plugin-builder

ARG TARGETOS
ARG TARGETARCH
# The hardened module floor forced into BOTH plugin graphs before compilation
# and proven on all three binaries below. Raise it here and in
# grafana/tests/image_hardening_contract_test.sh together.
ARG XNET_VERSION=v0.62.0
# PostgreSQL: Grafana's signed dependency-only commit after v13.0.5 (the
# v13.0.5 release zip below still supplies the frontend and plugin metadata).
ARG POSTGRES_PLUGIN_SOURCE_COMMIT=975580aadf51fa075e0181026abd0dcfb9f366dd
# Prometheus: the commit tag v13.2.6 points at (the v13.2.6 release zip below
# supplies the frontend and plugin metadata, so backend and frontend match).
ARG PROMETHEUS_PLUGIN_SOURCE_COMMIT=4911ab97610c140ef26f571eea63da95aa8b2e0c
# The plugin versions stamped into the rebuilt backends; the runtime stage
# redeclares the same two values for the release zips, and the contract test
# holds the pairs equal.
ARG PROMETHEUS_PLUGIN_VERSION=13.2.6
ARG POSTGRES_PLUGIN_VERSION=13.0.5

# GOTOOLCHAIN=local refuses a toolchain download, so the pinned builder is the
# compiler that ran (both plugins' go.mod say `go 1.27.3`).
ENV GOTOOLCHAIN=local CGO_ENABLED=0

WORKDIR /src

ADD --checksum=sha256:10e3b266e2d648f53e30add109f397aa59270fcc541b0ad44e8d5b97d6366b84 \
  https://codeload.github.com/grafana/grafana-postgresql-datasource/tar.gz/975580aadf51fa075e0181026abd0dcfb9f366dd \
  /tmp/postgres-plugin-source.tar.gz
ADD --checksum=sha256:d458ba84d5857ab48e241b4c4d21b19895938b97871a64d524d272c529dbcbf5 \
  https://codeload.github.com/grafana/grafana-prometheus-datasource/tar.gz/4911ab97610c140ef26f571eea63da95aa8b2e0c \
  /tmp/prometheus-plugin-source.tar.gz

RUN set -eux; \
    test "${POSTGRES_PLUGIN_SOURCE_COMMIT}" = "975580aadf51fa075e0181026abd0dcfb9f366dd"; \
    test "${PROMETHEUS_PLUGIN_SOURCE_COMMIT}" = "4911ab97610c140ef26f571eea63da95aa8b2e0c"; \
    mkdir -p /src/postgres /src/prometheus /out/postgres /out/prometheus /out/modules /proof/bin; \
    tar -xzf /tmp/postgres-plugin-source.tar.gz --strip-components=1 -C /src/postgres; \
    tar -xzf /tmp/prometheus-plugin-source.tar.gz --strip-components=1 -C /src/prometheus

# PostgreSQL backend: x/net to the floor, then the build the plugin SDK's
# Magefile performs (grafana-plugin-sdk-go build/common.go: `./pkg`, static via
# CGO_ENABLED=0, `-tags arrow_json_stdlib`, `-ldflags "-w -s"`, and the same
# -X flags the SDK passes: the effective stamp is buildinfo.buildInfoJSON, which
# the SDK reads back; main.pluginID and main.version name no symbol in these
# plugins and are carried only for parity). -trimpath is added on top for
# reproducible paths; the SDK does not pass it.
WORKDIR /src/postgres
RUN --mount=type=cache,target=/go/pkg/mod \
    go get golang.org/x/net@${XNET_VERSION}
RUN --mount=type=cache,target=/go/pkg/mod \
    GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
      go build -mod=mod -trimpath -buildvcs=false -tags arrow_json_stdlib \
      -ldflags "-w -s -X main.pluginID=grafana-postgresql-datasource -X main.version=${POSTGRES_PLUGIN_VERSION} -X github.com/grafana/grafana-plugin-sdk-go/build/buildinfo.buildInfoJSON={\"pluginID\":\"grafana-postgresql-datasource\",\"version\":\"${POSTGRES_PLUGIN_VERSION}\"}" \
      -o "/out/postgres/gpx_grafana_postgresql_datasource_linux_${TARGETARCH}" ./pkg

# Prometheus backend: the same, from the v13.2.6 source commit.
WORKDIR /src/prometheus
RUN --mount=type=cache,target=/go/pkg/mod \
    go get golang.org/x/net@${XNET_VERSION}
RUN --mount=type=cache,target=/go/pkg/mod \
    GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
      go build -mod=mod -trimpath -buildvcs=false -tags arrow_json_stdlib \
      -ldflags "-w -s -X main.pluginID=prometheus -X main.version=${PROMETHEUS_PLUGIN_VERSION} -X github.com/grafana/grafana-plugin-sdk-go/build/buildinfo.buildInfoJSON={\"pluginID\":\"prometheus\",\"version\":\"${PROMETHEUS_PLUGIN_VERSION}\"}" \
      -o "/out/prometheus/gpx_grafana-prometheus-datasource_linux_${TARGETARCH}" ./pkg

# THE PROOF. `go version -m` prints the module graph the linker embedded in a
# binary - the same data the image scanner reads. The upstream Grafana server
# binary and BOTH rebuilt backends are checked against the floor in one
# invocation, and the build fails if any one is below it. The listings ship in
# the image under /usr/share/grafana/modules/ so the claim can be re-read from
# the artifact itself. (The shipped image already depends on this stage through
# the backend COPYs below; the listings add the re-readable record.)
COPY check-go-module-floor.sh /usr/local/bin/check-go-module-floor.sh
COPY --from=grafana-upstream /usr/share/grafana/bin/grafana /proof/bin/grafana
RUN chmod 0555 /usr/local/bin/check-go-module-floor.sh \
  && go version -m /proof/bin/grafana > /out/modules/grafana.modules \
  && go version -m "/out/prometheus/gpx_grafana-prometheus-datasource_linux_${TARGETARCH}" > /out/modules/prometheus-datasource.modules \
  && go version -m "/out/postgres/gpx_grafana_postgresql_datasource_linux_${TARGETARCH}" > /out/modules/postgresql-datasource.modules \
  && /usr/local/bin/check-go-module-floor.sh golang.org/x/net "${XNET_VERSION}" \
    /out/modules/grafana.modules /out/modules/prometheus-datasource.modules /out/modules/postgresql-datasource.modules

FROM grafana-upstream AS runtime-base

ARG TARGETARCH
ARG PROMETHEUS_PLUGIN_VERSION=13.2.6
ARG POSTGRES_PLUGIN_VERSION=13.0.5

# Do not install or replace plugins at container startup, and do not expose the
# UI plugin installer. Upgrades belong in a reviewed image build with fresh
# checksums and dual-arch scans. The two data-source plugins are the only
# allowed unsigned IDs: their upstream signed release manifests cannot describe
# the dependency-fixed backends rebuilt above. The plugin tree is root-owned and
# non-writable by Grafana, and the whole OCI image is digest-pinned at deploy.
ENV GF_PLUGINS_PREINSTALL_DISABLED=true \
    GF_PLUGINS_PREINSTALL_AUTO_UPDATE=false \
    GF_PLUGINS_PLUGIN_ADMIN_ENABLED=false \
    GF_PLUGINS_ALLOW_LOADING_UNSIGNED_PLUGINS=grafana-postgresql-datasource,prometheus \
    GF_PLUGIN_CANVAS_AS_EXTERNAL=false

USER root

RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) \
        prometheus_sha="1384e582886998c505be71e33a7e6ab05eebb45aae5dd997a4bcfab478e6f503"; \
        postgres_sha="094c42befc67a484381b78d385bf759b9166f27d27cdcc620503c0964b3ba270" \
        ;; \
      arm64) \
        prometheus_sha="524b5825594ab292f09ea55bc005ad59ce9c51847725d5fdbc5ad3e23fb6c06c"; \
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
    rm -f /usr/share/grafana/data/plugins-bundled/grafana-postgresql-datasource/go_plugin_build_manifest; \
    rm -f /usr/share/grafana/data/plugins-bundled/prometheus/MANIFEST.txt; \
    rm -f /usr/share/grafana/data/plugins-bundled/prometheus/go_plugin_build_manifest; \
    chown -R root:root /usr/share/grafana/data/plugins-bundled; \
    chmod -R a-w /usr/share/grafana/data/plugins-bundled; \
    rm -f "${prometheus_archive}" "${postgres_archive}"

# Replace both release backends (built upstream with vulnerable x/net) with the
# binaries built above from the pinned source commits at the x/net floor.
COPY --from=plugin-builder --chown=root:root --chmod=0555 /out/postgres/ \
  /usr/share/grafana/data/plugins-bundled/grafana-postgresql-datasource/
COPY --from=plugin-builder --chown=root:root --chmod=0555 /out/prometheus/ \
  /usr/share/grafana/data/plugins-bundled/prometheus/

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

# Keep the production/release image as the Dockerfile's default final target,
# carrying the proof's module listings for re-reading.
FROM runtime-base AS release
COPY --from=plugin-builder --chown=root:root /out/modules/ /usr/share/grafana/modules/
