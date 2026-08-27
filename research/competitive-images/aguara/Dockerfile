# syntax=docker/dockerfile:1.7

FROM golang:1.25-alpine@sha256:5caaf1cca9dc351e13deafbc3879fd4754801acba8653fa9540cea125d01a71f AS dependencies
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

FROM dependencies AS builder
COPY . .
RUN --network=none CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/garagon/aguara/cmd/aguara/commands.Version=benchmark -X github.com/garagon/aguara/cmd/aguara/commands.Commit=819eafb5fa66" \
    -o /out/aguara ./cmd/aguara

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
COPY --from=builder /out/aguara /usr/local/bin/aguara
ENTRYPOINT ["/usr/local/bin/aguara"]
