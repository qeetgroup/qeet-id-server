# syntax=docker/dockerfile:1

# Base images are ARGs so CI/Renovate can pin them by digest without editing
# FROM lines. To pin: resolve the digest once and pass it as a build-arg, e.g.
#   docker buildx imagetools inspect golang:1.25-alpine            # -> sha256:...
#   docker build --build-arg GO_IMAGE=golang:1.25-alpine@sha256:<digest> ...
# Production builds (release CI) MUST pass digest-pinned values.
ARG GO_IMAGE=golang:1.25-alpine
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot

FROM ${GO_IMAGE} AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .

# Version metadata, injected by the build (see Makefile / CI). Defaults keep a
# bare `docker build` working; release CI passes the real values.
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown
ENV BUILDINFO=github.com/qeetgroup/qeet-id/internal/platform/buildinfo

# Static, stripped, version-stamped binary so it runs on distroless.
RUN CGO_ENABLED=0 go build \
    -ldflags="-s -w \
      -X ${BUILDINFO}.Version=${VERSION} \
      -X ${BUILDINFO}.Commit=${COMMIT} \
      -X ${BUILDINFO}.Date=${BUILD_DATE}" \
    -o /out/qeet-id ./cmd/server

# Distroless + nonroot: no shell, minimal attack surface. k8s probes hit
# /healthz and /readyz. The app listens on HTTP_PORT (default 4001); set it in
# the manifest/compose if you front it on a different port.
FROM ${RUNTIME_IMAGE}

# OCI image metadata (https://github.com/opencontainers/image-spec).
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.title="qeet-id" \
      org.opencontainers.image.description="Qeet ID — identity platform" \
      org.opencontainers.image.source="https://github.com/qeetgroup/qeet-id" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}"

COPY --from=build /out/qeet-id /qeet-id
EXPOSE 4001
USER nonroot:nonroot
ENTRYPOINT ["/qeet-id"]
