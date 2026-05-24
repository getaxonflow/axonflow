FROM golang:1.26-alpine AS builder
WORKDIR /build
COPY go.mod ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 go build -o /mock-llm .

FROM alpine:3.21
RUN addgroup -g 1001 -S mock && \
    adduser -S -D -H -u 1001 -G mock mock
COPY --from=builder /mock-llm /usr/local/bin/mock-llm
USER mock
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://localhost:9090/health || true
ENTRYPOINT ["mock-llm"]
