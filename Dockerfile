FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Cross-compile to the target arch on the native builder (fast, no emulation).
# TARGETOS/TARGETARCH are set by buildx from --platform; default to linux/amd64.
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /out/qeet-id-server ./cmd/api

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/qeet-id-server /qeet-id-server
EXPOSE 4001
USER nonroot:nonroot
ENTRYPOINT ["/qeet-id-server"]
