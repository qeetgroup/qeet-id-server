# Keep in step with go.mod's toolchain line: CI builds, tests and scans with that Go.
# Both bases are pinned by digest, so a rebuild of a commit uses the same bytes;
# move the tag and the digest together (docker buildx imagetools inspect <tag>).
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build
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

FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
COPY --from=build /out/qeet-id-server /qeet-id-server
# The API runs the scheduled jobs itself (embedded workers); the standalone
# scheduler is here for deployments that run them apart.
COPY --from=build /out/qeet-id-scheduler /qeet-id-scheduler
EXPOSE 4001
USER nonroot:nonroot
# SIGTERM starts a graceful stop that ends within SHUTDOWN_TIMEOUT (20s by
# default). Give the container longer before it is killed, 30s at the default:
# docker stop -t 30, compose stop_grace_period: 30s, ECS stopTimeout: 30 or
# Kubernetes terminationGracePeriodSeconds: 30. Docker's own default is 10s.
STOPSIGNAL SIGTERM
ENTRYPOINT ["/qeet-id-server"]
