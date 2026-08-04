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
ARG AXONFLOW_VERSION=9.14.0

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
# #3242: the OJK overlay was REMOVED from the block below, deliberately.
#
# That block used to run, for enterprise builds only:
#     cp -r /src/ee/platform/orchestrator/ojk/* ./orchestrator/ojk/
# which overlaid ee/platform/orchestrator/ojk ON TOP of the canonical
# platform/orchestrator/ojk that COPY had just placed here. The ee/ copy is a
# duplicate of the platform package with the `//go:build enterprise` header
# stripped. At the commit this overlay was removed, `diff` between the two showed
# exactly that two-line header and nothing else; the copies necessarily diverge
# once the platform package moves, which is the whole problem -- a duplicate that
# ships is a duplicate that goes stale silently.
#
# Consequences, both of which bit:
#
#  1. `ee/platform/orchestrator/ojk` is documented across this epic as a DEAD
#     MIRROR that no binary imports. That is true of `go build` in the repo and
#     FALSE of the shipped container: this overlay made the mirror the code that
#     actually ran. Any change to platform/orchestrator/ojk was invisible in
#     production.
#
#  2. Overlaying stale same-named files onto a package that has gained NEW files
#     does not produce the old package -- it produces a broken mixture. Adding
#     export_queries.go / framework.go / readiness.go / retention.go to
#     platform/ while the overlay restored the old ojk_audit_export_service.go
#     and types.go gave "method already declared" plus "undefined type" and the
#     image failed to build. runtime-e2e/3242_ojk_pii_export caught it; nothing
#     else did, because `go build -tags enterprise ./...` in the repo never sees
#     the overlay.
#
# The package is compiled with `-tags enterprise` for enterprise images anyway
# (see the go build invocation below), so the platform copy -- the one every
# test in the repo exercises -- is the correct and sufficient source.
#
# The sibling overlays are left ALONE here on purpose -- they belong to other
# workstreams in this epic and removing them unreviewed is a far wider blast
# radius than this change is scoped for. But they are NOT all the same, and
# saying so would be worse than saying nothing:
#
#   * sebi is a LIVE defect, not a latent one. platform/orchestrator/sebi wraps
#     three reads in withOrgScope (added for FORCE RLS on organizations /
#     audit_retention_config); the ee/ copy has NONE of them, and its own comment
#     says "if this package is ever re-wired, mirror the platform copy's
#     withOrgScope wrap BEFORE FORCE RLS goes live." The line below IS that
#     re-wiring: post-overlay the shipped sebi package has zero withOrgScope call
#     sites, on a service built against the app-role pool. Filed for the epic.
#
#   * rbi / euaiact / masfeat / llmadapters are genuinely latent: their copies
#     diverge only in tests and doc comments today.
#
#   * agents is a LATENT MIRROR, same class as ojk. CORRECTED 2026-08-03: an
#     earlier revision of this comment claimed "not a mirror at all, no platform
#     files exist". That was asserted without checking and is false.
#     platform/orchestrator/ee/agents/ holds 11 Go files on main; the agents
#     copy block below (grep this file for "orchestrator/agents" - line numbers
#     go stale) overlays ee/platform/orchestrator/agents/* onto them; the pair differs
#     ONLY by the two-line //go:build enterprise header (11 files x 2 lines,
#     nothing else); and the build below passes -tags enterprise, so the platform
#     copy compiles and removing the overlay would NOT break the build.
#     Left in place here regardless - it is out of this change's scope - but
#     stated truthfully, because an unverified negative in a comment like this
#     recreates the exact trap the comment exists to prevent.
# ---------------------------------------------------------------------------

# For enterprise builds from enterprise repo, copy ee/ agent code
# The orchestrator imports agent package which needs enterprise code for:
# - license, marketplace, node_enforcement (always)
# - rbi, hitl, circuitbreaker (EU AI Act Article 14, Issue #891)
# ADR-013: Enterprise repo always has ee/, Community repo doesn't have ee/
#
# NO COMPLIANCE-MODULE OVERLAY (#3244 / #3249 / #3241 round 2).
#
# This build used to `cp -r /src/ee/platform/orchestrator/{sebi,rbi,euaiact,
# masfeat}/*` OVER the platform tree. Those blocks are DELETED and must not come
# back. `scripts/ci/check-no-compliance-overlay.sh` fails the build if they do.
#
# The overlay was not a mirror that happened to be stale, it was a silent
# revert. The ee/ twins carry the same file names and the same signatures, so an
# overlaid build compiles cleanly and the newer platform file simply stops
# existing. Measured on origin/main before removal:
#
#   - platform/orchestrator/sebi has 3 live `withOrgScope(ctx, ...)` call sites;
#     the ee/ copy of sebi_audit_export_service.go has 0, and ee/sebi has no
#     rls_session.go at all. So the SHIPPED enterprise sebi ran those audit-export
#     reads with no `app.current_org_id` set, under FORCE RLS, while the helper
#     sat in the image defined-but-never-called. That is a live tenancy defect,
#     and it is the reason this is a removal rather than a re-sync.
#   - rbi, euaiact and masfeat differ from their platform twins ONLY in build
#     tags, `../` depth in test migration paths, and test comments - no
#     production-code drift - so removing their overlay changes no behaviour
#     beyond letting the platform tree's fixes actually ship.
#
# Nothing is lost: no ee/ compliance directory contains a .go file that platform/
# lacks - the only non-.go content is documentation (rbi/README.md, and the
# DEPRECATED.md markers added alongside this change). The platform copies are
# `//go:build enterprise` tagged and this build passes `-tags enterprise`, so
# they compile into the enterprise image exactly as before.
#
# ALL FIVE compliance mirrors are now un-overlaid (four removed here, ojk by the
# merged #3250). The blocks below still overlay ee/platform/orchestrator/
# {llmadapters,agents}, ee/platform/connectors and several ee/platform/agent/*
# modules - this is not a claim that the image is built from platform/ alone.
# llmadapters and agents are latent mirrors (see #3244); their removal is
# #3252's scope.
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
      echo "=== Copying EE compliance modules ===" && \
      echo "OJK compliance module: built from platform/orchestrator/ojk (see the note above the builder stage)" && \
      if [ -d "/src/ee/platform/orchestrator/llmadapters" ]; then \
        mkdir -p ./orchestrator/llmadapters/ && \
        cp -r /src/ee/platform/orchestrator/llmadapters/* ./orchestrator/llmadapters/ && \
        echo "LLM Adapters module copied (Bedrock support)"; \
      fi && \
      if [ -d "/src/ee/platform/orchestrator/agents" ]; then \
        mkdir -p ./orchestrator/ee/agents/ && \
        cp -r /src/ee/platform/orchestrator/agents/* ./orchestrator/ee/agents/ && \
        echo "Agent CRUD handler module copied (DB Agent Config)"; \
      fi && \
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

ARG AXONFLOW_VERSION=9.14.0
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
