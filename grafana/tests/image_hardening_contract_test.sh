#!/usr/bin/env bash
# Static release contract for the custom Grafana image. Runtime boot, plugin
# loading, and vulnerability checks are performed by the release train; this
# test prevents the source from silently returning to floating or full images,
# and pins the from-source rebuild of BOTH data-source backends at the x/net
# floor with its build-time proof (#4486, CVE-2026-78661).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DOCKERFILE="${GRAFANA_DOCKERFILE:-${SCRIPT_DIR}/../Dockerfile}"
CHECKER="${SCRIPT_DIR}/../check-go-module-floor.sh"
XNET_FLOOR=v0.62.0

fail() { echo "FAIL: $1" >&2; exit 1; }

# A byte-order mark is stripped by BuildKit and would reach every check below as
# a stray byte; refuse it first so the reason is honest.
test "$(head -c 3 "${DOCKERFILE}" | od -An -tx1 | tr -d ' \n')" != "efbbbf" \
  || fail "the file starts with a byte-order mark, which BuildKit strips and the checks below do not"
# ---- canonical form (shared by the image contracts) --------------------------
# BuildKit parses INSTRUCTIONS, not lines: it accepts leading whitespace and
# lowercase keywords, joins a `\`+newline continuation by appending the next
# line VERBATIM (so a token may be split across lines), and treats `\` followed
# by trailing blanks as a continuation too. A contract that greps raw lines
# therefore misses `ARG XNET_VER\` + `SION=v0.61.0`, an indented `  from ... AS
# plugin-builder`, or a split GF_ key. So: (1) refuse the forms that have no
# business here (indentation, lowercase keywords, blank-trailed continuations),
# and (2) build ONE normalised text the way BuildKit would read it (comment lines
# dropped, continuations joined verbatim, runs of spaces squeezed) that EVERY
# whitelist below reads.
if grep -nE '\\[[:space:]]+$' "${DOCKERFILE}" >/dev/null; then
  fail "a continuation backslash is followed by blanks (BuildKit still continues the line): $(grep -nE '\\[[:space:]]+$' "${DOCKERFILE}" | head -3 | tr '\n' '|')"
fi
canon="$(grep -Ev '^[[:space:]]*#' "${DOCKERFILE}" | sed -e ':a' -e '/\\$/N; s/\\\n//; ta' | tr -s ' ')"
while IFS= read -r instr; do
  [ -n "${instr}" ] || continue
  grep -Eq '^(FROM|ARG|ENV|RUN|COPY|ADD|WORKDIR|USER|ENTRYPOINT|CMD|HEALTHCHECK|EXPOSE|VOLUME|LABEL)( |$)' <<<"${instr}" \
    || fail "an instruction is not in canonical form (column-0 uppercase keyword), which the whitelists below cannot see: ${instr:0:120}"
done <<<"${canon}"
mentions() { awk -v needle="$1" 'BEGIN { n = 0 } { s = $0; while ((i = index(s, needle)) > 0) { n++; s = substr(s, i + length(needle)) } } END { print n }' <<<"${canon}"; }
# The parser directive selects the PROGRAM that interprets this file; it is a
# comment to every check that strips comments, so it is pinned by itself: line 1
# is exactly the pinned `# syntax=`, no byte-order mark precedes it, and no
# other directive-shaped comment (`# escape=`, `# check=`, anything BuildKit adds
# later) appears anywhere. Heredocs are refused outright: no Dockerfile here
# uses `<<`, and BuildKit accepts spellings (`<<\CMD`) a narrower regex misses.
test "$(head -n 1 "${DOCKERFILE}")" = '# syntax=docker/dockerfile:1.7' \
  || fail "line 1 must be exactly '# syntax=docker/dockerfile:1.7' (the parser directive), got: $(head -n 1 "${DOCKERFILE}")"
# BuildKit reads directives only as the leading run of `# key=value` comment
# lines; the first other line ends that run. So line 2 must not be
# directive-shaped (it would be a second directive: escape=, check=, ...), and a
# `# escape=` anywhere is refused regardless, since it is the one directive that
# would change which lines this contract joins.
if sed -n '2p' "${DOCKERFILE}" | grep -Eiq '^[[:space:]]*#[[:space:]]*[A-Za-z][A-Za-z0-9]*[[:space:]]*='; then
  fail "a second parser directive follows the syntax line: $(sed -n '2p' "${DOCKERFILE}")"
fi
if grep -Eiq '^[[:space:]]*#[[:space:]]*escape[[:space:]]*=' "${DOCKERFILE}"; then
  fail "a '# escape=' parser directive would change which lines BuildKit continues; this file must not set one"
fi
if grep -Eq '^(RUN|COPY|ADD) .*<<' <<<"${canon}"; then
  fail "a heredoc instruction would run text the keyword gate cannot classify; these Dockerfiles use none"
fi
# Nothing precedes the first FROM: a global ARG there is readable by every stage.
test -z "$(awk '/^FROM / { exit } NF' <<<"${canon}")" \
  || fail "instructions precede the first FROM: $(awk '/^FROM / { exit } NF' <<<"${canon}" | head -1)"

# --- base image -----------------------------------------------------------------
grep -Fxq 'FROM grafana/grafana:13.3.1-slim@sha256:49221b454a407632e47e6d4bbc2bb1585c462bf68c6fb9ebed4aa072b027595a AS grafana-upstream' "${DOCKERFILE}" \
  || fail "Grafana slim base must be 13.3.1 (first 13.3 with x/net v0.62.0 in the server), pinned by manifest digest, as the grafana-upstream stage"
grep -Fxq 'FROM grafana-upstream AS runtime-base' "${DOCKERFILE}" \
  || fail "runtime-base must build on the grafana-upstream stage"
if grep -Eq '^FROM[[:space:]]+grafana/grafana:(latest|10\.|11\.|12\.|13\.3\.0([^@-]|$)|13\.3\.0-slim)' "${DOCKERFILE}"; then
  fail "Grafana base is floating, non-slim, or from the vulnerable-era release line"
fi
# The whole ordered stage list, exactly. BuildKit resolves a DUPLICATED stage
# name to its LAST definition, so a second `AS plugin-builder` (or a second
# `AS release`) inserted anywhere would replace the proof or the shipped stage
# while every presence check in this file still passed.
expected_froms="$(printf '%s\n' \
  'FROM grafana/grafana:13.3.1-slim@sha256:49221b454a407632e47e6d4bbc2bb1585c462bf68c6fb9ebed4aa072b027595a AS grafana-upstream' \
  'FROM golang:1.27.3-alpine3.24@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS plugin-builder' \
  'FROM grafana-upstream AS runtime-base' \
  'FROM runtime-base AS otel' \
  'FROM runtime-base AS release')"
test "$(grep -E '^FROM ' <<<"${canon}")" = "${expected_froms}" \
  || fail "the stage list is not exactly grafana-upstream, plugin-builder, runtime-base, otel, release (a duplicated stage name silently replaces a stage): $(grep -E '^FROM ' <<<"${canon}" | tr '\n' '|')"
# Every ADD is checksum-pinned; a decoy pinned ADD beside an unpinned one must not count.
while IFS= read -r add_line; do
  grep -Eq -- '--checksum=sha256:[0-9a-f]{64}( |$)' <<<"${add_line}" \
    || fail "an ADD is not checksum-pinned: ${add_line}"
done < <(grep -E '^ADD ' <<<"${canon}")

# --- plugin releases (frontend + metadata) --------------------------------------
# Each plugin version is declared in the builder (stamped into the backend) and
# in runtime-base (the release zip): exactly two identical declarations each.
for pin in 'ARG PROMETHEUS_PLUGIN_VERSION=13.2.6' 'ARG POSTGRES_PLUGIN_VERSION=13.0.5'; do
  key="${pin%%=*}"
  test "$(grep -F -x "${pin}" "${DOCKERFILE}" | wc -l | tr -d ' ')" -eq 2 \
    || fail "${key} must be declared exactly twice (builder and runtime-base) as '${pin}'"
    test "$(printf '%s\n' "${canon}" | sed "s/\${${key}}//g" | grep -c -- "${key}")" -eq 2 \
    || fail "${key} is mentioned other than by its two identical declarations (references stripped)"
done
grep -Fxq 'ARG TEMPO_PLUGIN_VERSION=13.3.0' "${DOCKERFILE}" \
  || fail "Tempo plugin version is not pinned"
for checksum in \
  1384e582886998c505be71e33a7e6ab05eebb45aae5dd997a4bcfab478e6f503 \
  524b5825594ab292f09ea55bc005ad59ce9c51847725d5fdbc5ad3e23fb6c06c \
  094c42befc67a484381b78d385bf759b9166f27d27cdcc620503c0964b3ba270 \
  7c1569c906d99b2ad49ef6ab8abe8b0bb3b679577c6f8a72bbc8b06b1460d4f0 \
  692135f83a7430e54dd2aeaf89da7c3f7b7561ea7826582294910d7c59842bd1 \
  0f8dbee754eb6924d17c66b07fc5991b34ef446ffadfb1807f0d4468e0289e51; do
  grep -Fq "${checksum}" "${DOCKERFILE}" || fail "missing release-asset checksum ${checksum}"
done

# --- the from-source backends ---------------------------------------------------
grep -Fxq 'FROM golang:1.27.3-alpine3.24@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS plugin-builder' "${DOCKERFILE}" \
  || fail "plugin builder must be patched and digest-pinned"
grep -Fxq 'ARG POSTGRES_PLUGIN_SOURCE_COMMIT=975580aadf51fa075e0181026abd0dcfb9f366dd' "${DOCKERFILE}" \
  || fail "PostgreSQL backend source commit is not pinned"
grep -Fxq 'ARG PROMETHEUS_PLUGIN_SOURCE_COMMIT=4911ab97610c140ef26f571eea63da95aa8b2e0c' "${DOCKERFILE}" \
  || fail "Prometheus backend source commit is not pinned (tag v13.2.6)"
grep -Fq '10e3b266e2d648f53e30add109f397aa59270fcc541b0ad44e8d5b97d6366b84' "${DOCKERFILE}" \
  || fail "PostgreSQL backend source archive checksum is not pinned"
grep -Fq 'd458ba84d5857ab48e241b4c4d21b19895938b97871a64d524d272c529dbcbf5' "${DOCKERFILE}" \
  || fail "Prometheus backend source archive checksum is not pinned"
test "$(grep -c -- '--checksum=sha256:[0-9a-f]\{64\} ' "${DOCKERFILE}")" -eq 2 \
  || fail "expected exactly two checksum-pinned source archives (PostgreSQL + Prometheus)"
grep -Fxq 'ENV GOTOOLCHAIN=local CGO_ENABLED=0' "${DOCKERFILE}" \
  || fail "GOTOOLCHAIN=local is not the builder's one toolchain setting"
toolchain_lines="$(grep 'GOTOOLCHAIN' <<<"${canon}" || true)"
test "${toolchain_lines}" = 'ENV GOTOOLCHAIN=local CGO_ENABLED=0' \
  || fail "GOTOOLCHAIN is set other than by its one ENV line: ${toolchain_lines}"

# The floor: exactly one assignment, and both graphs moved to it before build.
grep -Fxq "ARG XNET_VERSION=${XNET_FLOOR}" "${DOCKERFILE}" \
  || fail "XNET_VERSION is not pinned to the floor ${XNET_FLOOR}"
xnet_lines="$(sed 's/\${XNET_VERSION}//g' <<<"${canon}" | grep 'XNET_VERSION' || true)"
test "${xnet_lines}" = "ARG XNET_VERSION=${XNET_FLOOR}" \
  || fail "XNET_VERSION is assigned or redeclared other than by its one ARG line: ${xnet_lines}"
# Each plugin's block (from its WORKDIR to the next WORKDIR or COPY) carries ONE
# go get and ONE go build, in that order, with the plugin SDK's own flags
# (grafana-plugin-sdk-go build/common.go): -tags arrow_json_stdlib, -ldflags
# "-w -s" plus the build-info and main.version/main.pluginID stamps, static via
# CGO_ENABLED=0; -trimpath added for reproducible paths. A count of two go gets
# would be satisfied by both on one plugin; per-block is not.
block_of() {
  awk -v start="WORKDIR /src/$1" '
    $0 == start { capture = 1; next }
    capture && (/^WORKDIR / || /^COPY /) { exit }
    capture && NF { print }
  ' <<<"${canon}"
}
pg_block="$(block_of postgres)"; prom_block="$(block_of prometheus)"
test -n "${pg_block}" || fail "the PostgreSQL build block could not be extracted"
test -n "${prom_block}" || fail "the Prometheus build block could not be extracted"
pg_build='RUN --mount=type=cache,target=/go/pkg/mod GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build -mod=mod -trimpath -buildvcs=false -tags arrow_json_stdlib -ldflags "-w -s -X main.pluginID=grafana-postgresql-datasource -X main.version=${POSTGRES_PLUGIN_VERSION} -X github.com/grafana/grafana-plugin-sdk-go/build/buildinfo.buildInfoJSON={\"pluginID\":\"grafana-postgresql-datasource\",\"version\":\"${POSTGRES_PLUGIN_VERSION}\"}" -o "/out/postgres/gpx_grafana_postgresql_datasource_linux_${TARGETARCH}" ./pkg'
prom_build='RUN --mount=type=cache,target=/go/pkg/mod GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build -mod=mod -trimpath -buildvcs=false -tags arrow_json_stdlib -ldflags "-w -s -X main.pluginID=prometheus -X main.version=${PROMETHEUS_PLUGIN_VERSION} -X github.com/grafana/grafana-plugin-sdk-go/build/buildinfo.buildInfoJSON={\"pluginID\":\"prometheus\",\"version\":\"${PROMETHEUS_PLUGIN_VERSION}\"}" -o "/out/prometheus/gpx_grafana-prometheus-datasource_linux_${TARGETARCH}" ./pkg'
go_get='RUN --mount=type=cache,target=/go/pkg/mod go get golang.org/x/net@${XNET_VERSION}'
for name in postgres prometheus; do
  case "${name}" in postgres) block="${pg_block}"; build="${pg_build}" ;; prometheus) block="${prom_block}"; build="${prom_build}" ;; esac
  test "${block}" = "$(printf '%s\n%s' "${go_get}" "${build}")" \
    || fail "the ${name} build block must be exactly one go get of \${XNET_VERSION} followed by the SDK-flagged go build from ./pkg, got: $(tr '\n' '|' <<<"${block}")"
done

# THE PROOF: server + both backends in one pure && chain, exactly those three.
test -x "${CHECKER}" || fail "grafana/check-go-module-floor.sh is missing or not executable"
cmp -s "${CHECKER}" "${SCRIPT_DIR}/../../platform/monitoring/check-go-module-floor.sh" \
  || fail "grafana/check-go-module-floor.sh must be byte-identical to platform/monitoring/check-go-module-floor.sh (one checker, two build contexts)"
grep -Fxq 'COPY check-go-module-floor.sh /usr/local/bin/check-go-module-floor.sh' "${DOCKERFILE}" \
  || fail "the floor checker is not copied into the builder"
grep -Fxq 'COPY --from=grafana-upstream /usr/share/grafana/bin/grafana /proof/bin/grafana' "${DOCKERFILE}" \
  || fail "the upstream server binary is not brought into the builder for the proof"
checker_call="$(grep -F 'check-go-module-floor.sh golang.org/x/net "${XNET_VERSION}"' <<<"${canon}" || true)"
test -n "${checker_call}" || fail "the build does not run check-go-module-floor.sh on golang.org/x/net at \${XNET_VERSION}"
if grep -Eq ';|\|\|' <<<"${checker_call}"; then
  fail "the proof instruction contains ';' or '||'; it must be a pure && chain so a failing step fails the layer"
fi
grep -Fq 'RUN chmod 0555 /usr/local/bin/check-go-module-floor.sh && go version -m /proof/bin/grafana > /out/modules/grafana.modules && go version -m "/out/prometheus/gpx_grafana-prometheus-datasource_linux_${TARGETARCH}" > /out/modules/prometheus-datasource.modules && go version -m "/out/postgres/gpx_grafana_postgresql_datasource_linux_${TARGETARCH}" > /out/modules/postgresql-datasource.modules && /usr/local/bin/check-go-module-floor.sh' <<<"$(tr -s ' ' <<<"${checker_call}")" \
  || fail "the proof instruction is not the expected chain (chmod, three independent go version -m listings, then the checker): ${checker_call}"
checker_args="$(sed 's/.*check-go-module-floor\.sh golang\.org\/x\/net "\${XNET_VERSION}"//' <<<"${checker_call}")"
[[ "${checker_args}" =~ ^[[:space:]]*/out/modules/grafana\.modules[[:space:]]+/out/modules/prometheus-datasource\.modules[[:space:]]+/out/modules/postgresql-datasource\.modules[[:space:]]*$ ]] \
  || fail "the floor check's arguments must be exactly the server, Prometheus and PostgreSQL listings, got:${checker_args}"
test "$(mentions check-go-module-floor.sh)" -eq 4 \
  || fail "check-go-module-floor.sh is mentioned other than in its COPY, chmod and call (by name); a redefinition would replace the proof"
# The shipped stage depends on the proof through the module listings.
grep -Fxq 'COPY --from=plugin-builder --chown=root:root /out/modules/ /usr/share/grafana/modules/' "${DOCKERFILE}" \
  || fail "the release stage does not copy the module listings, so it would not depend on the proof"

# --- runtime hardening ----------------------------------------------------------
grep -Fxq 'COPY --from=plugin-builder --chown=root:root --chmod=0555 /out/postgres/ /usr/share/grafana/data/plugins-bundled/grafana-postgresql-datasource/' <<<"${canon}" \
  || fail "the rebuilt PostgreSQL backend does not replace the release backend (whole COPY, destination included)"
grep -Fxq 'COPY --from=plugin-builder --chown=root:root --chmod=0555 /out/prometheus/ /usr/share/grafana/data/plugins-bundled/prometheus/' <<<"${canon}" \
  || fail "the rebuilt Prometheus backend does not replace the release backend (whole COPY, destination included)"
for plugin in grafana-postgresql-datasource prometheus; do
  for manifest in MANIFEST.txt go_plugin_build_manifest; do
    grep -Fq "rm -f /usr/share/grafana/data/plugins-bundled/${plugin}/${manifest}; " <<<"${canon}" \
      || fail "the ${plugin} plugin's stale ${manifest} must be removed (exact path, terminated)"
  done
done
# The proven artifacts are the shipped artifacts, by name: every non-comment
# mention of each path is one of the known instructions, so a second COPY onto
# /proof/bin/grafana, a cp over a backend after the proof, an echo into a
# listing, or a COPY over the shipped server binary is a count change here.
for pair in '/proof/bin/grafana:2' '/out/modules:8' '/out/prometheus:4' '/out/postgres:4' '/usr/share/grafana/bin/grafana:1' 'MANIFEST.txt:2' 'go_plugin_build_manifest:2'; do
  path="${pair%:*}"; want="${pair##*:}"
  test "$(mentions "${path}")" -eq "${want}" \
    || fail "${path} is mentioned $(mentions "${path}") time(s) on non-comment lines, expected ${want}; a proven artifact may have been replaced after the proof"
done
# The plugin hardening ENV is ONE whitelisted instruction, and every non-comment
# mention of each key is that instruction: a later `ENV GF_PLUGINS_...` that
# widened the unsigned list or re-enabled the plugin admin would be a second
# mention and fails here.
plugins_env='ENV GF_PLUGINS_PREINSTALL_DISABLED=true GF_PLUGINS_PREINSTALL_AUTO_UPDATE=false GF_PLUGINS_PLUGIN_ADMIN_ENABLED=false GF_PLUGINS_ALLOW_LOADING_UNSIGNED_PLUGINS=grafana-postgresql-datasource,prometheus GF_PLUGIN_CANVAS_AS_EXTERNAL=false'
grep -Fxq "${plugins_env}" <<<"${canon}" \
  || fail "the plugin hardening ENV is not the one expected instruction (preinstall disabled, no auto-update, no plugin admin, unsigned exception exactly the two rebuilt data sources, core Canvas fallback)"
for key in GF_PLUGINS_PREINSTALL_DISABLED GF_PLUGINS_PREINSTALL_AUTO_UPDATE GF_PLUGINS_PLUGIN_ADMIN_ENABLED GF_PLUGINS_ALLOW_LOADING_UNSIGNED_PLUGINS GF_PLUGIN_CANVAS_AS_EXTERNAL; do
  test "$(grep -F -- "${key}" <<<"${canon}")" = "${plugins_env}" \
    || fail "${key} is set other than by the one plugin hardening ENV: $(grep -F -- "${key}" <<<"${canon}" | tr '\n' '|')"
done
grep -Fq 'chown -R root:root /usr/share/grafana/data/plugins-bundled' "${DOCKERFILE}" \
  || fail "bundled plugins must remain root-owned"
grep -Fq 'chmod -R a-w /usr/share/grafana/data/plugins-bundled' "${DOCKERFILE}" \
  || fail "bundled plugins must remain non-writable at runtime"
grep -Fxq 'FROM runtime-base AS otel' "${DOCKERFILE}" \
  || fail "Tempo must remain isolated to the optional OTel target"
grep -Fxq 'FROM runtime-base AS release' "${DOCKERFILE}" \
  || fail "the Tempo-free production target must remain the default final stage"
test "$(grep -E '^FROM ' <<<"${canon}" | tail -n 1)" = 'FROM runtime-base AS release' \
  || fail "the release stage must be LAST so a build with no --target ships it"

# ---- golden stages: the durable close ---------------------------------------
# Every whitelist above names a thing that must or must not appear; a path the
# shell spells (`/out/"prometheus"/`, `${P}etheus`, a glob) is invisible to a
# literal count. So the normalised text of each SHIPPED stage must equal this
# pin exactly: nothing can be inserted, reordered or respelled anywhere in them.
# ALL five stages are pinned, including grafana-upstream (the base every shipped
# stage inherits and the source of the server binary the proof measures).
# Change the Dockerfile deliberately, then re-pin here in the same commit.
stage_text() {
  awk -v name="$1" '
    /^FROM / { if (cap) exit; cap = ($0 ~ (" AS " name "$")); if (cap) print; next }
    cap && NF { print }
  ' <<<"${canon}"
}
expected_plugin_builder="$(cat <<'GOLDEN'
FROM golang:1.27.3-alpine3.24@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS plugin-builder
ARG TARGETOS
ARG TARGETARCH
ARG XNET_VERSION=v0.62.0
ARG POSTGRES_PLUGIN_SOURCE_COMMIT=975580aadf51fa075e0181026abd0dcfb9f366dd
ARG PROMETHEUS_PLUGIN_SOURCE_COMMIT=4911ab97610c140ef26f571eea63da95aa8b2e0c
ARG PROMETHEUS_PLUGIN_VERSION=13.2.6
ARG POSTGRES_PLUGIN_VERSION=13.0.5
ENV GOTOOLCHAIN=local CGO_ENABLED=0
WORKDIR /src
ADD --checksum=sha256:10e3b266e2d648f53e30add109f397aa59270fcc541b0ad44e8d5b97d6366b84 https://codeload.github.com/grafana/grafana-postgresql-datasource/tar.gz/975580aadf51fa075e0181026abd0dcfb9f366dd /tmp/postgres-plugin-source.tar.gz
ADD --checksum=sha256:d458ba84d5857ab48e241b4c4d21b19895938b97871a64d524d272c529dbcbf5 https://codeload.github.com/grafana/grafana-prometheus-datasource/tar.gz/4911ab97610c140ef26f571eea63da95aa8b2e0c /tmp/prometheus-plugin-source.tar.gz
RUN set -eux; test "${POSTGRES_PLUGIN_SOURCE_COMMIT}" = "975580aadf51fa075e0181026abd0dcfb9f366dd"; test "${PROMETHEUS_PLUGIN_SOURCE_COMMIT}" = "4911ab97610c140ef26f571eea63da95aa8b2e0c"; mkdir -p /src/postgres /src/prometheus /out/postgres /out/prometheus /out/modules /proof/bin; tar -xzf /tmp/postgres-plugin-source.tar.gz --strip-components=1 -C /src/postgres; tar -xzf /tmp/prometheus-plugin-source.tar.gz --strip-components=1 -C /src/prometheus
WORKDIR /src/postgres
RUN --mount=type=cache,target=/go/pkg/mod go get golang.org/x/net@${XNET_VERSION}
RUN --mount=type=cache,target=/go/pkg/mod GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build -mod=mod -trimpath -buildvcs=false -tags arrow_json_stdlib -ldflags "-w -s -X main.pluginID=grafana-postgresql-datasource -X main.version=${POSTGRES_PLUGIN_VERSION} -X github.com/grafana/grafana-plugin-sdk-go/build/buildinfo.buildInfoJSON={\"pluginID\":\"grafana-postgresql-datasource\",\"version\":\"${POSTGRES_PLUGIN_VERSION}\"}" -o "/out/postgres/gpx_grafana_postgresql_datasource_linux_${TARGETARCH}" ./pkg
WORKDIR /src/prometheus
RUN --mount=type=cache,target=/go/pkg/mod go get golang.org/x/net@${XNET_VERSION}
RUN --mount=type=cache,target=/go/pkg/mod GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build -mod=mod -trimpath -buildvcs=false -tags arrow_json_stdlib -ldflags "-w -s -X main.pluginID=prometheus -X main.version=${PROMETHEUS_PLUGIN_VERSION} -X github.com/grafana/grafana-plugin-sdk-go/build/buildinfo.buildInfoJSON={\"pluginID\":\"prometheus\",\"version\":\"${PROMETHEUS_PLUGIN_VERSION}\"}" -o "/out/prometheus/gpx_grafana-prometheus-datasource_linux_${TARGETARCH}" ./pkg
COPY check-go-module-floor.sh /usr/local/bin/check-go-module-floor.sh
COPY --from=grafana-upstream /usr/share/grafana/bin/grafana /proof/bin/grafana
RUN chmod 0555 /usr/local/bin/check-go-module-floor.sh && go version -m /proof/bin/grafana > /out/modules/grafana.modules && go version -m "/out/prometheus/gpx_grafana-prometheus-datasource_linux_${TARGETARCH}" > /out/modules/prometheus-datasource.modules && go version -m "/out/postgres/gpx_grafana_postgresql_datasource_linux_${TARGETARCH}" > /out/modules/postgresql-datasource.modules && /usr/local/bin/check-go-module-floor.sh golang.org/x/net "${XNET_VERSION}" /out/modules/grafana.modules /out/modules/prometheus-datasource.modules /out/modules/postgresql-datasource.modules
GOLDEN
)"
test "$(stage_text plugin-builder)" = "${expected_plugin_builder}" \
  || fail "the normalised plugin-builder stage differs from its pin (every instruction in a shipped stage is pinned; re-pin deliberately with the change): $(diff <(printf '%s\n' "${expected_plugin_builder}") <(stage_text plugin-builder) | head -5 | tr '\n' '|')"
expected_runtime_base="$(cat <<'GOLDEN'
FROM grafana-upstream AS runtime-base
ARG TARGETARCH
ARG PROMETHEUS_PLUGIN_VERSION=13.2.6
ARG POSTGRES_PLUGIN_VERSION=13.0.5
ENV GF_PLUGINS_PREINSTALL_DISABLED=true GF_PLUGINS_PREINSTALL_AUTO_UPDATE=false GF_PLUGINS_PLUGIN_ADMIN_ENABLED=false GF_PLUGINS_ALLOW_LOADING_UNSIGNED_PLUGINS=grafana-postgresql-datasource,prometheus GF_PLUGIN_CANVAS_AS_EXTERNAL=false
USER root
RUN set -eux; case "${TARGETARCH}" in amd64) prometheus_sha="1384e582886998c505be71e33a7e6ab05eebb45aae5dd997a4bcfab478e6f503"; postgres_sha="094c42befc67a484381b78d385bf759b9166f27d27cdcc620503c0964b3ba270" ;; arm64) prometheus_sha="524b5825594ab292f09ea55bc005ad59ce9c51847725d5fdbc5ad3e23fb6c06c"; postgres_sha="7c1569c906d99b2ad49ef6ab8abe8b0bb3b679577c6f8a72bbc8b06b1460d4f0" ;; *) echo "unsupported release architecture: ${TARGETARCH}" >&2; exit 1 ;; esac; prometheus_archive="/tmp/prometheus.zip"; postgres_archive="/tmp/postgres.zip"; wget -q -O "${prometheus_archive}" "https://github.com/grafana/grafana-prometheus-datasource/releases/download/v${PROMETHEUS_PLUGIN_VERSION}/prometheus-${PROMETHEUS_PLUGIN_VERSION}.linux_${TARGETARCH}.zip"; wget -q -O "${postgres_archive}" "https://github.com/grafana/grafana-postgresql-datasource/releases/download/v${POSTGRES_PLUGIN_VERSION}/grafana-postgresql-datasource-${POSTGRES_PLUGIN_VERSION}.linux_${TARGETARCH}.zip"; echo "${prometheus_sha} ${prometheus_archive}" | sha256sum -c -; echo "${postgres_sha} ${postgres_archive}" | sha256sum -c -; unzip -q "${prometheus_archive}" -d /usr/share/grafana/data/plugins-bundled; unzip -q "${postgres_archive}" -d /usr/share/grafana/data/plugins-bundled; test -x "/usr/share/grafana/data/plugins-bundled/prometheus/gpx_grafana-prometheus-datasource_linux_${TARGETARCH}"; test -x "/usr/share/grafana/data/plugins-bundled/grafana-postgresql-datasource/gpx_grafana_postgresql_datasource_linux_${TARGETARCH}"; rm -f /usr/share/grafana/data/plugins-bundled/grafana-postgresql-datasource/MANIFEST.txt; rm -f /usr/share/grafana/data/plugins-bundled/grafana-postgresql-datasource/go_plugin_build_manifest; rm -f /usr/share/grafana/data/plugins-bundled/prometheus/MANIFEST.txt; rm -f /usr/share/grafana/data/plugins-bundled/prometheus/go_plugin_build_manifest; chown -R root:root /usr/share/grafana/data/plugins-bundled; chmod -R a-w /usr/share/grafana/data/plugins-bundled; rm -f "${prometheus_archive}" "${postgres_archive}"
COPY --from=plugin-builder --chown=root:root --chmod=0555 /out/postgres/ /usr/share/grafana/data/plugins-bundled/grafana-postgresql-datasource/
COPY --from=plugin-builder --chown=root:root --chmod=0555 /out/prometheus/ /usr/share/grafana/data/plugins-bundled/prometheus/
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh
COPY provisioning/dashboards/dashboards.yaml /etc/grafana/provisioning/dashboards/dashboards.yaml
COPY dashboards/*.json /var/lib/grafana/dashboards/
USER grafana
ENTRYPOINT ["/docker-entrypoint.sh"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD wget -q --spider http://localhost:3000/api/health || exit 1
CMD []
GOLDEN
)"
test "$(stage_text runtime-base)" = "${expected_runtime_base}" \
  || fail "the normalised runtime-base stage differs from its pin (every instruction in a shipped stage is pinned; re-pin deliberately with the change): $(diff <(printf '%s\n' "${expected_runtime_base}") <(stage_text runtime-base) | head -5 | tr '\n' '|')"
expected_release="$(cat <<'GOLDEN'
FROM runtime-base AS release
COPY --from=plugin-builder --chown=root:root /out/modules/ /usr/share/grafana/modules/
GOLDEN
)"
test "$(stage_text release)" = "${expected_release}" \
  || fail "the normalised release stage differs from its pin (every instruction in a shipped stage is pinned; re-pin deliberately with the change): $(diff <(printf '%s\n' "${expected_release}") <(stage_text release) | head -5 | tr '\n' '|')"

expected_grafana_upstream="$(cat <<'GOLDEN'
FROM grafana/grafana:13.3.1-slim@sha256:49221b454a407632e47e6d4bbc2bb1585c462bf68c6fb9ebed4aa072b027595a AS grafana-upstream
GOLDEN
)"
test "$(stage_text grafana-upstream)" = "${expected_grafana_upstream}" \
  || fail "the normalised grafana-upstream stage differs from its pin (every stage is pinned; re-pin deliberately with the change): $(diff <(printf '%s\n' "${expected_grafana_upstream}") <(stage_text grafana-upstream) | head -5 | tr '\n' '|')"
expected_otel="$(cat <<'GOLDEN'
FROM runtime-base AS otel
ARG TARGETARCH
ARG TEMPO_PLUGIN_VERSION=13.3.0
USER root
RUN set -eux; case "${TARGETARCH}" in amd64) tempo_sha="692135f83a7430e54dd2aeaf89da7c3f7b7561ea7826582294910d7c59842bd1" ;; arm64) tempo_sha="0f8dbee754eb6924d17c66b07fc5991b34ef446ffadfb1807f0d4468e0289e51" ;; *) echo "unsupported OTel architecture: ${TARGETARCH}" >&2; exit 1 ;; esac; tempo_archive="/tmp/tempo.zip"; wget -q -O "${tempo_archive}" "https://github.com/grafana/grafana-tempo-datasource/releases/download/v${TEMPO_PLUGIN_VERSION}/tempo-${TEMPO_PLUGIN_VERSION}.linux_${TARGETARCH}.zip"; echo "${tempo_sha} ${tempo_archive}" | sha256sum -c -; unzip -q "${tempo_archive}" -d /usr/share/grafana/data/plugins-bundled; test -x "/usr/share/grafana/data/plugins-bundled/tempo/gpx_grafana-tempo-datasource_linux_${TARGETARCH}"; chown -R root:root /usr/share/grafana/data/plugins-bundled/tempo; chmod -R a-w /usr/share/grafana/data/plugins-bundled/tempo; rm -f "${tempo_archive}"
USER grafana
GOLDEN
)"
test "$(stage_text otel)" = "${expected_otel}" \
  || fail "the normalised otel stage differs from its pin (every stage is pinned; re-pin deliberately with the change): $(diff <(printf '%s\n' "${expected_otel}") <(stage_text otel) | head -5 | tr '\n' '|')"

echo "PASS: Grafana 13.3.1 base and both data-source backends are immutable, rebuilt at golang.org/x/net >= ${XNET_FLOOR} with the floor proven on the server and both backends, and drift-disabled"
