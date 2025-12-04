# Multi-stage Docker build for AxonFlow Demo API
FROM golang:1.21-alpine AS builder

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set Go environment variables to force proxy usage
ENV GOPROXY=https://proxy.golang.org
ENV GOSUMDB=sum.golang.org
ENV GOPRIVATE=""
ENV GONOPROXY=""
ENV GONOSUMDB=""
ENV GOVCS="*:off"

# Copy go mod and go.sum files for dependency caching
COPY go.mod go.sum* ./

# Download dependencies first (better caching)
RUN go mod download

# Copy all source files
COPY . ./

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# Final stage - minimal runtime image
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates curl tzdata

# Create non-root user
RUN addgroup -g 1001 -S axonflow && \
    adduser -S -D -H -u 1001 -h /app -s /sbin/nologin -G axonflow -g axonflow axonflow

WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/main .

# Change ownership
RUN chown -R axonflow:axonflow /app

# Switch to non-root user
USER axonflow

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run the application
CMD ["./main"]