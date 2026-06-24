# syntax=docker/dockerfile:1
ARG GO_IMAGE=golang:1.25-alpine
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot

FROM ${GO_IMAGE} AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown
ENV BUILDINFO=github.com/qeetgroup/qeet-id/platform/observability/buildinfo

RUN CGO_ENABLED=0 go build \
    -ldflags="-s -w \
      -X ${BUILDINFO}.Version=${VERSION} \
      -X ${BUILDINFO}.Commit=${COMMIT} \
      -X ${BUILDINFO}.Date=${BUILD_DATE}" \
    -o /out/qeet-id ./cmd/server

FROM ${RUNTIME_IMAGE}
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
