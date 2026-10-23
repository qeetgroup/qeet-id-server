# Keep in step with go.mod's toolchain line: CI builds, tests and scans with that Go.
# Both bases are pinned by digest, so a rebuild of a commit uses the same bytes;
# move the tag and the digest together (docker buildx imagetools inspect <tag>).
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Cross-compile to the target arch on the native builder (fast, no emulation).
# TARGETOS/TARGETARCH are set by buildx from --platform; default to linux/amd64.
ARG TARGETOS=linux
ARG TARGETARCH=amd64
# Build metadata surfaced on /healthz and the build_info metric. Defaults match
# an unstamped build, so a plain `docker build` behaves exactly as before.
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-X github.com/qeetgroup/qeet-id-server/internal/platform/observability/buildinfo.Version=${VERSION} \
                -X github.com/qeetgroup/qeet-id-server/internal/platform/observability/buildinfo.Commit=${COMMIT} \
                -X github.com/qeetgroup/qeet-id-server/internal/platform/observability/buildinfo.Date=${DATE}" \
      -o /out/qeet-id-server ./cmd/api && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-X github.com/qeetgroup/qeet-id-server/internal/platform/observability/buildinfo.Version=${VERSION} \
                -X github.com/qeetgroup/qeet-id-server/internal/platform/observability/buildinfo.Commit=${COMMIT} \
                -X github.com/qeetgroup/qeet-id-server/internal/platform/observability/buildinfo.Date=${DATE}" \
      -o /out/qeet-id-scheduler ./cmd/scheduler

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/qeet-id-server /qeet-id-server
# The API runs the scheduled jobs itself (embedded workers); the standalone
# scheduler is here for deployments that run them apart.
COPY --from=build /out/qeet-id-scheduler /qeet-id-scheduler
EXPOSE 4001
USER nonroot:nonroot
ENTRYPOINT ["/qeet-id-server"]
