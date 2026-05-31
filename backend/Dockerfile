FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download || true
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/qeet-id ./cmd/server

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/qeet-id /qeet-id
EXPOSE 4000
ENTRYPOINT ["/qeet-id"]
