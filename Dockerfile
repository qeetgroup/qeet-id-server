FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/qeet-id ./cmd/api

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/qeet-id /qeet-id
EXPOSE 4001
USER nonroot:nonroot
ENTRYPOINT ["/qeet-id"]
