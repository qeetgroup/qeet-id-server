# syntax=docker/dockerfile:1
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
# Static, stripped binary so it runs on distroless.
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/qeet-id ./cmd/server

# Distroless + nonroot: no shell, minimal attack surface. k8s probes hit
# /healthz and /readyz; HTTP_PORT defaults to 4001 in our manifests.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/qeet-id /qeet-id
EXPOSE 4001
USER nonroot:nonroot
ENTRYPOINT ["/qeet-id"]
