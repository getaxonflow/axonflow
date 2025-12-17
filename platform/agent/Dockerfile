# Multi-stage build for AxonFlow Agent
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

# For enterprise builds from enterprise repo, copy ee/ code to overlay OSS stubs
# ADR-013: Enterprise repo always has ee/, OSS repo doesn't have ee/
# IMPORTANT: Only copy EE code for EDITION=enterprise to avoid dependency issues
# The EE code has dependencies (AWS SDK) not in platform/go.mod
RUN --mount=type=bind,source=.,target=/src \
    if [ "$EDITION" = "enterprise" ] && [ -d "/src/ee/platform/agent/license" ]; then \
      echo "=== Enterprise build: copying EE agent code ===" && \
      cp -r /src/ee/platform/agent/license/* ./agent/license/ && \
      cp -r /src/ee/platform/agent/marketplace/* ./agent/marketplace/ && \
      cp -r /src/ee/platform/agent/node_enforcement/* ./agent/node_enforcement/ && \
      if [ -d "/src/ee/platform/agent/rbi" ]; then \
        cp -r /src/ee/platform/agent/rbi/* ./agent/rbi/ && \
        echo "  Copied enterprise RBI module"; \
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
      if [ -d "/src/ee/platform/agent/sqli" ]; then \
        mkdir -p /go/src/axonflow/ee/platform/agent/sqli && \
        cp -r /src/ee/platform/agent/sqli/* /go/src/axonflow/ee/platform/agent/sqli/ && \
        echo "module axonflow/ee/platform" > /go/src/axonflow/ee/platform/go.mod && \
        echo "" >> /go/src/axonflow/ee/platform/go.mod && \
        echo "go 1.24.0" >> /go/src/axonflow/ee/platform/go.mod && \
        echo "" >> /go/src/axonflow/ee/platform/go.mod && \
        echo "require axonflow/platform v0.0.0" >> /go/src/axonflow/ee/platform/go.mod && \
        echo "" >> /go/src/axonflow/ee/platform/go.mod && \
        echo "replace axonflow/platform => /go/src/axonflow/platform" >> /go/src/axonflow/ee/platform/go.mod && \
        go mod edit -require axonflow/ee/platform@v0.0.0 && \
        go mod edit -replace axonflow/ee/platform=/go/src/axonflow/ee/platform && \
        echo "  Copied enterprise SQLi scanner (ML-based) and configured modules"; \
      fi && \
      echo "Enterprise agent code copied successfully" && \
      echo "=== Enterprise build: copying EE connectors ===" && \
      for connector in amadeus salesforce slack snowflake hubspot jira servicenow; do \
        if [ -d "/src/ee/platform/connectors/$connector" ]; then \
          cp -r /src/ee/platform/connectors/$connector/* ./connectors/$connector/ && \
          echo "  Copied enterprise connector: $connector"; \
        fi; \
      done && \
      echo "Enterprise connectors copied successfully" && \
      echo "=== Downloading enterprise dependencies ===" && \
      go get github.com/aws/aws-sdk-go-v2/service/marketplacemetering@latest && \
      go get github.com/snowflakedb/gosnowflake@latest && \
      echo "Enterprise dependencies downloaded"; \
    elif [ "$EDITION" = "enterprise" ]; then \
      echo "ERROR: Enterprise build requested but ee/ directory not found" && exit 1; \
    else \
      echo "=== OSS build: using stub implementations ==="; \
    fi

# Build the agent binary from cmd/agent entry point
# For enterprise builds, include the enterprise tag
# For OSS builds, no tag is needed (uses OSS stubs)
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo \
    $(if [ "$EDITION" = "enterprise" ]; then echo "-tags enterprise"; fi) \
    -o /app/agent ./cmd/agent

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
LABEL name="AxonFlow Agent" \
      vendor="AxonFlow, Inc." \
      version="1.0.0" \
      release="1" \
      summary="AxonFlow AI Control Plane - Agent Component" \
      description="Sub-10ms policy enforcement engine for AI governance. Evaluates policies, routes requests to orchestrator, and provides audit trail." \
      maintainer="AxonFlow, Inc. <support@getaxonflow.com>" \
      url="https://getaxonflow.com" \
      documentation="https://docs.getaxonflow.com" \
      license="Commercial" \
      io.k8s.description="AxonFlow Agent - AI governance and policy enforcement" \
      io.k8s.display-name="AxonFlow Agent" \
      io.opencontainer.image.title="AxonFlow Agent" \
      io.opencontainer.image.description="Sub-10ms policy enforcement for AI systems" \
      io.opencontainer.image.version="1.0.0" \
      io.opencontainer.image.vendor="AxonFlow, Inc." \
      io.opencontainer.image.licenses="Commercial" \
      io.opencontainer.image.url="https://getaxonflow.com" \
      io.opencontainer.image.documentation="https://docs.getaxonflow.com"

RUN apk --no-cache add ca-certificates curl tzdata

# Create non-root user
RUN addgroup -g 1001 -S axonflow && \
    adduser -S -D -H -u 1001 -h /app -s /sbin/nologin -G axonflow -g axonflow axonflow

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/agent .

# Copy migrations from the prep stage (includes EE migrations for enterprise builds)
# Migration files are sorted alphabetically (001_, 002_, etc.) and executed in order
# For enterprise: OSS + EE migrations merged; For OSS: only OSS migrations
COPY --from=migrations-prep /migrations/ /app/migrations/

# Change ownership
RUN chown -R axonflow:axonflow /app

# Switch to non-root user
USER axonflow

# Set default port
ENV PORT=8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:${PORT}/health || exit 1

# Expose port
EXPOSE ${PORT}

# Run the agent
CMD ["./agent"]
