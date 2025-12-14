# Multi-stage build for AxonFlow Orchestrator
FROM golang:1.25-alpine AS builder

# Build argument for edition (oss or enterprise)
# Default to oss - enterprise builds must explicitly set EDITION=enterprise
ARG EDITION=oss

# Install git for go modules
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory to match module path (axonflow/platform)
WORKDIR /go/src/axonflow/platform

# Copy go.mod and go.sum from platform root (build context is repo root)
COPY platform/go.mod platform/go.sum* ./

# Download dependencies
RUN go mod download

# Copy all source code from platform directory (OSS core code)
COPY platform/ .

# For enterprise builds from enterprise repo, copy ee/ agent code
# The orchestrator imports agent/node_enforcement which needs enterprise code
# ADR-013: Enterprise repo always has ee/, OSS repo doesn't have ee/
RUN --mount=type=bind,source=.,target=/src \
    if [ "$EDITION" = "enterprise" ] && [ -d "/src/ee/platform/agent/node_enforcement" ]; then \
      echo "=== Enterprise build: copying EE agent code for orchestrator ===" && \
      cp -r /src/ee/platform/agent/license/* ./agent/license/ && \
      cp -r /src/ee/platform/agent/marketplace/* ./agent/marketplace/ && \
      cp -r /src/ee/platform/agent/node_enforcement/* ./agent/node_enforcement/ && \
      echo "Enterprise agent code copied successfully" && \
      echo "=== Copying EE compliance modules ===" && \
      if [ -d "/src/ee/platform/orchestrator/sebi" ]; then \
        cp -r /src/ee/platform/orchestrator/sebi/* ./orchestrator/sebi/ && \
        echo "SEBI compliance module copied"; \
      fi && \
      if [ -d "/src/ee/platform/orchestrator/rbi" ]; then \
        mkdir -p ./orchestrator/rbi/ && \
        cp -r /src/ee/platform/orchestrator/rbi/* ./orchestrator/rbi/ && \
        echo "RBI compliance module copied"; \
      fi && \
      if [ -d "/src/ee/platform/orchestrator/euaiact" ]; then \
        mkdir -p ./orchestrator/euaiact/ && \
        cp -r /src/ee/platform/orchestrator/euaiact/* ./orchestrator/euaiact/ && \
        echo "EU AI Act compliance module copied"; \
      fi && \
      echo "=== Downloading enterprise dependencies ===" && \
      go get github.com/aws/aws-sdk-go-v2/service/marketplacemetering@latest && \
      echo "Enterprise dependencies downloaded"; \
    elif [ "$EDITION" = "enterprise" ]; then \
      echo "ERROR: Enterprise build requested but ee/ directory not found" && exit 1; \
    else \
      echo "=== OSS build: using stub implementations ==="; \
    fi

# Build the orchestrator binary from cmd/orchestrator entry point
# The orchestrator package is imported as a library by cmd/orchestrator/main.go
# For enterprise builds, include the enterprise tag
# For OSS builds, no tag is needed (uses OSS stubs)
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo \
    $(if [ "$EDITION" = "enterprise" ]; then echo "-tags enterprise"; fi) \
    -o /app/orchestrator ./cmd/orchestrator

# Migration preparation stage (ADR-012: Multi-Edition Migration Architecture)
# Directory structure: migrations/core/, migrations/enterprise/, migrations/industry/
#
# Build simplicity: Each repo only contains its own migrations
# - OSS repo: Only has migrations/core/
# - Enterprise repo: Has migrations/core/, migrations/enterprise/, migrations/industry/
# Just copy what exists - no conditional logic needed
FROM alpine:3.22 AS migrations-prep

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
      for ind in healthcare banking; do \
        if [ -d "/migrations/industry/$ind" ]; then \
          count=$(find /migrations/industry/$ind -name '*.sql' ! -name '*_down.sql' 2>/dev/null | wc -l); \
          echo "industry/$ind: $count files"; \
        fi; \
      done; \
    fi && \
    total=$(find /migrations -name '*.sql' ! -name '*_down.sql' 2>/dev/null | wc -l) && \
    echo "Total: $total migration files"

# Final stage - minimal runtime image
FROM alpine:3.22

# AWS Marketplace metadata
LABEL name="AxonFlow Orchestrator" \
      vendor="AxonFlow Inc" \
      version="1.0.0" \
      release="1" \
      summary="AxonFlow AI Control Plane - Orchestrator Component" \
      description="Multi-Agent Planning (MAP) orchestrator for coordinating AI agents in parallel with dependency management and autonomous execution." \
      maintainer="AxonFlow Inc <support@getaxonflow.com>" \
      url="https://getaxonflow.com" \
      documentation="https://docs.getaxonflow.com" \
      license="Commercial" \
      io.k8s.description="AxonFlow Orchestrator - Multi-agent planning and execution" \
      io.k8s.display-name="AxonFlow Orchestrator" \
      io.opencontainer.image.title="AxonFlow Orchestrator" \
      io.opencontainer.image.description="Multi-Agent Planning orchestrator for AI systems" \
      io.opencontainer.image.version="1.0.0" \
      io.opencontainer.image.vendor="AxonFlow Inc" \
      io.opencontainer.image.licenses="Commercial" \
      io.opencontainer.image.url="https://getaxonflow.com" \
      io.opencontainer.image.documentation="https://docs.getaxonflow.com"

RUN apk --no-cache add ca-certificates curl tzdata

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
