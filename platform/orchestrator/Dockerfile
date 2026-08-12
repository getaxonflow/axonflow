# Multi-stage build for AxonFlow Orchestrator
FROM golang:1.26-alpine AS builder

# Build argument for edition (community or enterprise)
# Default to community - enterprise builds must explicitly set EDITION=enterprise
ARG EDITION=community

# Platform version, baked into the binary via -X ldflags (#2662) so /health
# reports the true shipped version and cannot be spoofed by a runtime env var.
# Fed by build.yml's AXONFLOW_VERSION build-arg (read from the repo VERSION file)
# — the SAME source as the io.opencontainer.image.version label below, so the
# baked binary version and the image label never drift. Re-declared here in the
# builder stage (ARG scope is per-stage); the final stage declares it again.
ARG AXONFLOW_VERSION=9.17.0

# Install git for go modules
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory to match module path (axonflow/platform)
WORKDIR /go/src/axonflow/platform

# Copy go.mod and go.sum from platform root (build context is repo root)
COPY platform/go.mod platform/go.sum* ./

# Download dependencies
RUN go mod download

# Copy all source code from platform directory (Community core code)
COPY platform/ .

# ---------------------------------------------------------------------------
# NO ee/platform/orchestrator OVERLAY. NOT ONE. (#3252, closing #3244.)
#
# This build used to copy ee/platform/orchestrator/{ojk,sebi,rbi,euaiact,
# masfeat,llmadapters,agents} ON TOP of the platform packages that COPY had just
# placed here. All seven blocks are gone, and the seven directories were deleted
# with them, so there is no longer a second copy for a future block to point at.
# `scripts/ci/check-no-compliance-overlay.sh` fails the build if any reference to
# ee/platform/orchestrator reappears.
#
# WHY THIS MATTERED, kept because the failure mode is not obvious from the code.
#
# The ee/ twins carried the same file names and the same signatures with the
# `//go:build enterprise` header stripped. So an overlaid build compiled
# cleanly and the newer platform file simply stopped existing in the image: a
# fix landed in platform/, passed every test, and never shipped. Nothing in the
# repo could see it. `go build -tags enterprise ./...`, `go vet` and every unit
# test operate on the source tree, which has no overlay.
#
# Two measured consequences, both of which bit:
#
#  1. SILENT REVERT WITH A SECURITY EDGE. platform/orchestrator/sebi wraps three
#     audit-export reads in withOrgScope; the ee/ copy had ZERO, and no
#     rls_session.go at all. The shipped enterprise sebi therefore ran those
#     reads with no app.current_org_id set, under FORCE RLS, while the helper sat
#     in the image defined-but-never-called (#3241).
#
#  2. BROKEN MIXTURE, NOT AN OLD PACKAGE. Overlaying stale same-named files onto
#     a package that has gained NEW files gives "method already declared" plus
#     "undefined type". Adding export_queries.go / framework.go / readiness.go /
#     retention.go to platform/ojk while the overlay restored the old
#     ojk_audit_export_service.go and types.go failed the image build.
#     runtime-e2e/3242_ojk_pii_export caught it; nothing else did (#3242).
#
# The platform packages are `//go:build enterprise` tagged and this build passes
# `-tags enterprise`, so they compile into the enterprise image exactly as the
# overlaid copies did.
#
# WHAT IS STILL OVERLAID, so this is not misread as "built from platform/ alone":
# ee/platform/agent/* (license, marketplace, node_enforcement, rbi, hitl,
# circuitbreaker) and ee/platform/connectors, in the RUN block below. Those are a
# different arrangement - they overlay packages that are STUBS in the platform
# tree rather than full implementations - and they are out of #3252's scope.
# ---------------------------------------------------------------------------

# For enterprise builds from enterprise repo, copy ee/ agent code
# The orchestrator imports agent package which needs enterprise code for:
# - license, marketplace, node_enforcement (always)
# - rbi, hitl, circuitbreaker (EU AI Act Article 14, Issue #891)
# ADR-013: Enterprise repo always has ee/, Community repo doesn't have ee/
RUN --mount=type=bind,source=.,target=/src \
    if [ "$EDITION" = "enterprise" ] && [ -d "/src/ee/platform/agent/node_enforcement" ]; then \
      echo "=== Enterprise build: copying EE agent code for orchestrator ===" && \
      cp -r /src/ee/platform/agent/license/* ./agent/license/ && \
      cp -r /src/ee/platform/agent/marketplace/* ./agent/marketplace/ && \
      cp -r /src/ee/platform/agent/node_enforcement/* ./agent/node_enforcement/ && \
      if [ -d "/src/ee/platform/agent/rbi" ]; then \
        cp -r /src/ee/platform/agent/rbi/* ./agent/rbi/ && \
        echo "  Copied enterprise RBI agent module"; \
      fi && \
      if [ -d "/src/ee/platform/agent/hitl" ]; then \
        mkdir -p ./agent/hitl && \
        cp -r /src/ee/platform/agent/hitl/* ./agent/hitl/ && \
        echo "  Copied enterprise HITL module (EU AI Act Article 14)"; \
      fi && \
      if [ -d "/src/ee/platform/agent/circuitbreaker" ]; then \
        mkdir -p ./agent/circuitbreaker && \
        cp -r /src/ee/platform/agent/circuitbreaker/* ./agent/circuitbreaker/ && \
        echo "  Copied enterprise Circuit Breaker module (EU AI Act Article 14)"; \
      fi && \
      echo "Enterprise agent code copied successfully" && \
      echo "=== EE orchestrator modules: none. All seven are built from platform/ (#3252) ===" && \
      echo "=== Copying EE connectors ===" && \
      if [ -d "/src/ee/platform/connectors" ]; then \
        cp -r /src/ee/platform/connectors/* ./connectors/ && \
        echo "Enterprise connectors copied"; \
      fi && \
      echo "=== Downloading enterprise dependencies ===" && \
      go get github.com/aws/aws-sdk-go-v2/service/marketplacemetering@latest && \
      go get github.com/aws/aws-sdk-go-v2/service/bedrockruntime@latest && \
      go get github.com/snowflakedb/gosnowflake@latest && \
      echo "Enterprise dependencies downloaded"; \
    elif [ "$EDITION" = "enterprise" ]; then \
      echo "ERROR: Enterprise build requested but ee/ directory not found" && exit 1; \
    else \
      echo "=== Community build: using stub implementations ==="; \
    fi

# Build the orchestrator binary from cmd/orchestrator entry point
# The orchestrator package is imported as a library by cmd/orchestrator/main.go
# For enterprise builds, include the enterprise tag
# For Community builds, no tag is needed (uses Community stubs)
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo \
    -trimpath -ldflags="-s -w -X axonflow/platform/shared/version.Version=${AXONFLOW_VERSION}" \
    $(if [ "$EDITION" = "enterprise" ]; then echo "-tags enterprise"; fi) \
    -o /app/orchestrator ./cmd/orchestrator

# Migration preparation stage (ADR-012: Multi-Edition Migration Architecture)
# Directory structure: migrations/core/, migrations/enterprise/, migrations/industry/
#
# Build simplicity: Each repo only contains its own migrations
# - Community repo: Only has migrations/core/
# - Enterprise repo: Has migrations/core/, migrations/enterprise/, migrations/industry/
# Just copy what exists - no conditional logic needed
FROM alpine:3.24 AS migrations-prep

# Copy migrations directory as-is from the repo
COPY migrations/ /migrations/

# Log migration counts for build visibility
RUN set -e && \
    echo "=== Migration files included in build ===" && \
    for dir in core enterprise; do \
      if [ -d "/migrations/$dir" ]; then \
        count=$(find /migrations/$dir -name '*.sql' ! -name '*_down.sql' 2>/dev/null | wc -l); \
        echo "$dir: $count files"; \
      fi; \
    done && \
    if [ -d "/migrations/industry" ]; then \
      for ind in healthcare banking travel; do \
        if [ -d "/migrations/industry/$ind" ]; then \
          count=$(find /migrations/industry/$ind -name '*.sql' ! -name '*_down.sql' 2>/dev/null | wc -l); \
          echo "industry/$ind: $count files"; \
        fi; \
      done; \
    fi && \
    total=$(find /migrations -name '*.sql' ! -name '*_down.sql' 2>/dev/null | wc -l) && \
    echo "Total: $total migration files"

# Final stage - minimal runtime image
FROM alpine:3.24

ARG AXONFLOW_VERSION=9.17.0
ENV AXONFLOW_VERSION=${AXONFLOW_VERSION}

# AWS Marketplace metadata
LABEL name="AxonFlow Orchestrator" \
      vendor="AxonFlow, Inc." \
      version="${AXONFLOW_VERSION}" \
      release="1" \
      summary="AxonFlow AI Control Plane - Orchestrator Component" \
      description="Multi-Agent Planning (MAP) orchestrator for coordinating AI agents in parallel with dependency management and autonomous execution." \
      maintainer="AxonFlow, Inc. <support@getaxonflow.com>" \
      url="https://getaxonflow.com" \
      documentation="https://docs.getaxonflow.com" \
      license="Commercial" \
      io.k8s.description="AxonFlow Orchestrator - Multi-agent planning and execution" \
      io.k8s.display-name="AxonFlow Orchestrator" \
      io.opencontainer.image.title="AxonFlow Orchestrator" \
      io.opencontainer.image.description="Multi-Agent Planning orchestrator for AI systems" \
      io.opencontainer.image.version="${AXONFLOW_VERSION}" \
      io.opencontainer.image.vendor="AxonFlow, Inc." \
      io.opencontainer.image.licenses="Commercial" \
      io.opencontainer.image.url="https://getaxonflow.com" \
      io.opencontainer.image.documentation="https://docs.getaxonflow.com"

# Install runtime deps and upgrade libssl3/libcrypto3 to pick up the
# CVE-2026-45447 patch (OpenSSL 3.5.6-r0 -> >= 3.5.7-r0). The upgrade pulls
# the latest patched build from the alpine 3.24 repo at build time.
RUN apk --no-cache add ca-certificates curl tzdata && \
    apk --no-cache upgrade libssl3 libcrypto3

# Create non-root user
RUN addgroup -g 1001 -S axonflow && \
    adduser -S -D -H -u 1001 -h /app -s /sbin/nologin -G axonflow -g axonflow axonflow

WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/orchestrator .

# Copy migrations from the prep stage (includes EE migrations for enterprise builds)
# Migration files are sorted alphabetically (001_, 002_, etc.) and executed in order
# For enterprise: OSS + EE migrations merged; For OSS: only OSS migrations
COPY --from=migrations-prep /migrations/ /app/migrations/

# Change ownership
RUN chown -R axonflow:axonflow /app

# Switch to non-root user
USER axonflow

# Set default port from centralized config
ENV PORT=8081

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:${PORT}/health || exit 1

# Expose port (dynamic via ENV)
EXPOSE ${PORT}

# Run the orchestrator binary directly
CMD ["./orchestrator"]
