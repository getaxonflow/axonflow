FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY main.go ./
RUN CGO_ENABLED=0 go build -o mcp-adapter .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates && \
    addgroup -g 1001 -S adapter && \
    adduser -S -D -H -u 1001 -G adapter adapter
COPY --from=builder /app/mcp-adapter /usr/local/bin/mcp-adapter
USER adapter
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://localhost:9090/health || true
ENTRYPOINT ["mcp-adapter"]
