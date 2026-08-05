# syntax=docker/dockerfile:1.7

FROM golang:1.23-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download || true

COPY . .

ARG TARGETOS
ARG TARGETARCH

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
    -ldflags="-s -w" \
    -o /out/server ./cmd/server

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
    -ldflags="-s -w" \
    -o /out/client ./cmd/client

FROM gcr.io/distroless/static-debian12:nonroot AS server

WORKDIR /app

COPY --from=builder /out/server /app/server
COPY configs/fingerprints.yaml /app/configs/fingerprints.yaml

USER nonroot:nonroot

EXPOSE 8080

ENTRYPOINT ["/app/server"]
