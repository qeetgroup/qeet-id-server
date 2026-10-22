# Keep in step with go.mod's toolchain line: CI builds, tests and scans with that Go.
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine AS build
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
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
      -ldflags "-X github.com/qeetgroup/qeet-id-server/internal/platform/observability/buildinfo.Version=${VERSION} \
                -X github.com/qeetgroup/qeet-id-server/internal/platform/observability/buildinfo.Commit=${COMMIT} \
                -X github.com/qeetgroup/qeet-id-server/internal/platform/observability/buildinfo.Date=${DATE}" \
      -o /out/qeet-id-server ./cmd/api && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
      -ldflags "-X github.com/qeetgroup/qeet-id-server/internal/platform/observability/buildinfo.Version=${VERSION} \
                -X github.com/qeetgroup/qeet-id-server/internal/platform/observability/buildinfo.Commit=${COMMIT} \
                -X github.com/qeetgroup/qeet-id-server/internal/platform/observability/buildinfo.Date=${DATE}" \
      -o /out/qeet-id-scheduler ./cmd/scheduler

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/qeet-id-server /qeet-id-server
# The API runs the scheduled jobs itself (embedded workers); the standalone
# scheduler is here for deployments that run them apart.
COPY --from=build /out/qeet-id-scheduler /qeet-id-scheduler
EXPOSE 4001
USER nonroot:nonroot
ENTRYPOINT ["/qeet-id-server"]
