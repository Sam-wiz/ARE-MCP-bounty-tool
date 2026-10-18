# syntax=docker/dockerfile:1
FROM golang:1.26.9-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=local
ARG REVISION=working-tree
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.Version=${VERSION} -X main.Revision=${REVISION}" -o /out/server ./cmd/server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 app && useradd --uid 10001 --gid app --home-dir /app --no-create-home app \
    && mkdir -p /app/bounties && chown -R 10001:10001 /app
WORKDIR /app
COPY --from=build /out/server /app/server
COPY plugins /app/plugins
COPY config/config.example.yaml /app/config/config.yaml
ENV SERVER_TRANSPORT=http HTTP_ADDR=0.0.0.0:8080 WORKSPACE_DIR=/app/bounties
USER 10001:10001
EXPOSE 8080
STOPSIGNAL SIGTERM
ENTRYPOINT ["/app/server"]
