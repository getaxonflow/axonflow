# syntax=docker/dockerfile:1.7

# MinIO stopped publishing anonymously pullable Community images in 2026.
# Build the final upstream Community releases from their immutable source
# commits instead of depending on a registry tag that can disappear. The
# source archives are checksum-pinned, and both binaries retain upstream's
# AGPL-3.0 licence notices in the runtime image.
FROM --platform=$BUILDPLATFORM golang:1.26.10-alpine@sha256:a2012b4a1d1f9f7e9f44e0d39b805a901e856b1dd80b4e6ee4338db547050308 AS builder

ARG TARGETOS=linux
ARG TARGETARCH

ARG MINIO_COMMIT=9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a
ARG MINIO_VERSION=2025-10-15T17:29:55Z
ARG MINIO_RELEASE=RELEASE.2025-10-15T17-29-55Z
ARG MC_COMMIT=7394ce0dd2a80935aded936b09fa12cbb3cb8096
ARG MC_VERSION=2025-08-13T08:35:41Z
ARG MC_RELEASE=RELEASE.2025-08-13T08-35-41Z

RUN apk add --no-cache ca-certificates

ADD --checksum=sha256:45521908307306e925c98d629e1c17d78c8b72b6ee242b1bfb1409f7d8ee5841 \
  https://codeload.github.com/minio/minio/tar.gz/9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a /tmp/minio.tar.gz
ADD --checksum=sha256:95cd293c7119f16921a6dc515a1fb74a2227f19fd994b9c8b770a154e802ac44 \
  https://codeload.github.com/minio/mc/tar.gz/7394ce0dd2a80935aded936b09fa12cbb3cb8096 /tmp/mc.tar.gz

RUN mkdir -p /src/minio /src/mc /out/licenses/minio /out/licenses/mc \
  && tar -xzf /tmp/minio.tar.gz --strip-components=1 -C /src/minio \
  && tar -xzf /tmp/mc.tar.gz --strip-components=1 -C /src/mc \
  && cp /src/minio/LICENSE /src/minio/CREDITS /out/licenses/minio/ \
  && cp /src/mc/LICENSE /src/mc/CREDITS /out/licenses/mc/

WORKDIR /src/minio
RUN --mount=type=cache,target=/go/pkg/mod \
  go get \
    github.com/apache/thrift@v0.24.0 \
    github.com/buger/jsonparser@v1.1.2 \
    github.com/go-jose/go-jose/v4@v4.1.6 \
    github.com/klauspost/compress@v1.19.0 \
    github.com/prometheus/prometheus@v0.311.3 \
    github.com/rabbitmq/amqp091-go@v1.13.0 \
    go.opentelemetry.io/otel/sdk@v1.44.0 \
    golang.org/x/crypto@v0.57.0 \
    golang.org/x/net@v0.60.0 \
    golang.org/x/text@v0.42.0 \
    google.golang.org/grpc@v1.83.2
RUN --mount=type=cache,target=/go/pkg/mod \
  CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
  go build -mod=mod -tags kqueue -trimpath -buildvcs=false \
  -ldflags="-s -w \
    -X github.com/minio/minio/cmd.Version=${MINIO_VERSION} \
    -X github.com/minio/minio/cmd.CopyrightYear=2025 \
    -X github.com/minio/minio/cmd.ReleaseTag=${MINIO_RELEASE} \
    -X github.com/minio/minio/cmd.CommitID=${MINIO_COMMIT} \
    -X github.com/minio/minio/cmd.ShortCommitID=9e49d5e7a648 \
    -X github.com/minio/minio/cmd.GOPATH=/go \
    -X github.com/minio/minio/cmd.GOROOT=/usr/local/go" \
  -o /out/minio .

WORKDIR /src/mc
RUN --mount=type=cache,target=/go/pkg/mod \
  go get \
    github.com/klauspost/compress@v1.19.0 \
    github.com/prometheus/prometheus@v0.311.3 \
    golang.org/x/crypto@v0.57.0 \
    golang.org/x/net@v0.60.0 \
    golang.org/x/text@v0.42.0 \
    google.golang.org/grpc@v1.83.2
RUN --mount=type=cache,target=/go/pkg/mod \
  CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
  go build -mod=mod -tags kqueue -trimpath -buildvcs=false \
  -ldflags="-s -w \
    -X github.com/minio/mc/cmd.Version=${MC_VERSION} \
    -X github.com/minio/mc/cmd.CopyrightYear=2025 \
    -X github.com/minio/mc/cmd.ReleaseTag=${MC_RELEASE} \
    -X github.com/minio/mc/cmd.CommitID=${MC_COMMIT} \
    -X github.com/minio/mc/cmd.ShortCommitID=7394ce0dd2a8" \
  -o /out/mc .

FROM alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a

RUN apk add --no-cache ca-certificates tzdata \
  && addgroup -S -g 1001 minio \
  && adduser -S -D -H -u 1001 -G minio minio \
  && mkdir -p /data /licenses/minio /licenses/mc \
  && chown minio:minio /data

COPY --from=builder --chmod=0555 /out/minio /usr/local/bin/minio
COPY --from=builder --chmod=0555 /out/mc /usr/local/bin/mc
COPY --from=builder /out/licenses/minio/ /licenses/minio/
COPY --from=builder /out/licenses/mc/ /licenses/mc/

ENV MC_CONFIG_DIR=/tmp/.mc

EXPOSE 9000 9001
VOLUME ["/data"]
USER minio
ENTRYPOINT ["minio"]
CMD ["server", "/data"]
