# Multi-stage build for the AxonFlow Gateway Adapters (#2886)
# Serves the agentgateway/Envoy PEP seams (ExtMcp + ext_authz + ext_proc) on one
# gRPC listener, translating to the AxonFlow Decision Mode engine (PDP >= 9.7.0).
# Source-available under BSL 1.1 and carried by the community mirror (#3657
# item 10). There is still no EDITION build arg: this image is built without
# the enterprise tag, and the binary reports whichever edition it was
# compiled as — see the note on the build step below.
#
# Build context is the REPO ROOT. The binary now lives in the ROOT module
# (axonflow/platform) rather than in axonflow/ee, so nothing here needs the ee
# module or its replace directives:
#   docker build -f platform/gateway-adapters/cmd/axonflow-gateway-adapters/Dockerfile .

# Cross-compile on the build platform (CGO_ENABLED=0 → no emulation needed for
# the compile step; TARGETOS/TARGETARCH are provided by buildx per platform leg).
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

# Platform version, baked into the BINARY via -X ldflags — the same mechanism
# platform/agent/Dockerfile and platform/orchestrator/Dockerfile use, fed by the
# same AXONFLOW_VERSION build-arg build.yml already passes to this image
# (`add gateway-adapters ... version_args=true`).
#
# WHY IT IS LOAD-BEARING NOW (#3660). The final stage below already declared
# this arg, but only for the image LABEL — nothing reached the binary, so
# version.Resolve() answered "" inside it. The checkpoint receiver REJECTS a
# platform-class ping with no platform_version (a row with no version dimension
# is useless for the adoption analysis platform telemetry exists for), and the
# emitter contract is to swallow a non-2xx. The adapter's startup ping would
# therefore have been dropped with HTTP 400, silently, forever — the exact
# invisibility this train is closing.
ARG AXONFLOW_VERSION=10.4.0

RUN apk add --no-cache git ca-certificates

WORKDIR /go/src/axonflow

# Module files first so dependency downloads cache independently of source edits.
# The ee module's replace directives point at local paths (../platform and the
# nested customer-portal module), so every replace target's go.mod must be in
# place before `go mod download` can resolve the build list.
COPY platform/go.mod platform/go.sum platform/
# platform/go.mod carries `replace axonflow/platform/decision => ./decision`,
# and `go mod download` resolves the whole module graph including local
# replacements - so the replaced module's manifest must exist at THIS layer,
# before any source is copied. Without it the build fails with
# "reading decision/go.mod: no such file or directory".
COPY platform/decision/go.mod platform/decision/go.sum platform/decision/
RUN cd platform && go mod download

COPY platform/ platform/

# Static build: CGO disabled, trimmed paths, stripped symbols. The adapter has
# no cgo dependencies, so the binary runs on any base (alpine here).
# NO `-tags enterprise`, AND THAT IS NOW LOAD-BEARING RATHER THAN INCIDENTAL.
# This package moved into the community-syncable tree under BSL 1.1, so
# edition.Current — which the binary reports on its telemetry ping — answers
# from the build tag. Building this image without the tag is what makes an
# enterprise-distributed artifact report `community`, so if this image is ever
# shipped AS Enterprise, add the tag here rather than pinning the constant in
# telemetry.go. See the comment on gatewayadapters.Edition.
RUN cd platform && CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w -X axonflow/platform/shared/version.Version=${AXONFLOW_VERSION}" \
    -o /out/axonflow-gateway-adapters \
    ./gateway-adapters/cmd/axonflow-gateway-adapters

# grpc_health_probe for exec-based health checks (docker HEALTHCHECK below and
# ECS container healthCheck): the adapter serves standard gRPC health
# (grpc.health.v1.Health) but a gRPC service has no HTTP /health for curl.
# Built from source (pinned) so the probe is also static and multi-arch.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go install github.com/grpc-ecosystem/grpc-health-probe@v0.4.53 && \
    if [ -x "/go/bin/${TARGETOS}_${TARGETARCH}/grpc-health-probe" ]; then \
      cp "/go/bin/${TARGETOS}_${TARGETARCH}/grpc-health-probe" /out/grpc_health_probe; \
    else \
      cp /go/bin/grpc-health-probe /out/grpc_health_probe; \
    fi

# Final stage - minimal runtime image
FROM alpine:3.24

ARG AXONFLOW_VERSION=10.4.0
ARG GIT_COMMIT=unknown
ARG BUILD_DATE=unknown
ENV AXONFLOW_VERSION=${AXONFLOW_VERSION}

LABEL name="AxonFlow Gateway Adapters" \
      vendor="AxonFlow, Inc." \
      version="${AXONFLOW_VERSION}" \
      release="1" \
      summary="AxonFlow AI Control Plane - Gateway Adapters (agentgateway/Envoy PEP)" \
      description="ExtMcp + ext_authz + ext_proc gRPC policy services translating gateway callouts to the AxonFlow Decision Mode engine. Zero local policy logic; requires PDP >= 9.7.0." \
      maintainer="AxonFlow, Inc. <support@getaxonflow.com>" \
      url="https://getaxonflow.com" \
      documentation="https://docs.getaxonflow.com/docs/integration/agentgateway" \
      license="Commercial" \
      io.k8s.description="AxonFlow Gateway Adapters - agentgateway/Envoy PEP seams for AI governance" \
      io.k8s.display-name="AxonFlow Gateway Adapters" \
      io.opencontainer.image.title="AxonFlow Gateway Adapters" \
      io.opencontainer.image.description="agentgateway/Envoy PEP adapters for the AxonFlow Decision Mode engine" \
      io.opencontainer.image.version="${AXONFLOW_VERSION}" \
      io.opencontainer.image.revision="${GIT_COMMIT}" \
      io.opencontainer.image.created="${BUILD_DATE}" \
      io.opencontainer.image.vendor="AxonFlow, Inc." \
      io.opencontainer.image.licenses="Commercial" \
      io.opencontainer.image.source="https://github.com/getaxonflow/axonflow-enterprise" \
      io.opencontainer.image.url="https://getaxonflow.com" \
      io.opencontainer.image.documentation="https://docs.getaxonflow.com/docs/integration/agentgateway"

# ca-certificates: the PDP endpoint may be HTTPS (Go reads the system roots).
# tzdata: consistent time handling. The libssl/libcrypto upgrade matches the
# agent/orchestrator images' CVE hygiene for the shared alpine base.
RUN apk --no-cache add ca-certificates tzdata && \
    apk --no-cache upgrade libssl3 libcrypto3

# Non-root user (same uid/gid convention as the other platform images)
RUN addgroup -g 1001 -S axonflow && \
    adduser -S -D -H -u 1001 -h /app -s /sbin/nologin -G axonflow -g axonflow axonflow

WORKDIR /app

COPY --from=builder /out/axonflow-gateway-adapters .
COPY --from=builder /out/grpc_health_probe /usr/local/bin/grpc_health_probe

RUN chown -R axonflow:axonflow /app

USER axonflow

# All three gRPC services + grpc.health.v1.Health on one listener.
# GATEWAY_ADAPTERS_LISTEN is the same env the binary reads (see config.go);
# the shell-form HEALTHCHECK follows an override without a rebuild.
ENV GATEWAY_ADAPTERS_LISTEN=:9090

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD grpc_health_probe -addr="${GATEWAY_ADAPTERS_LISTEN}" || exit 1

EXPOSE 9090

ENTRYPOINT ["./axonflow-gateway-adapters"]
