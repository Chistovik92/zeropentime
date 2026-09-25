# syntax=docker/dockerfile:1
# Контроллер zeropentime: админ-панель + API для узлов.
# Сборка из корня репозитория:  docker build -f deploy/Dockerfile -t zeropentime-controller .
# Готовый образ: ghcr.io/chistovik92/zeropentime-controller

# Компиляция идёт на платформе сборщика (быстро и для arm64).
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/zpt-controller ./cmd/zpt-controller

FROM alpine:3.22
RUN apk add --no-cache ca-certificates \
 && adduser -D -H -u 10001 zpt \
 && mkdir /data && chown zpt /data
COPY --from=build /out/zpt-controller /usr/local/bin/zpt-controller
COPY LICENSE.AGPL LICENSING.md TRADEMARKS.md /usr/share/doc/zeropentime/
USER zpt
VOLUME /data
EXPOSE 8080 3478/udp 3479/udp
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
  CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null || exit 1
LABEL org.opencontainers.image.title="zeropentime controller" \
      org.opencontainers.image.description="Админ-панель и API для узлов zeropentime" \
      org.opencontainers.image.source="https://github.com/Chistovik92/zeropentime" \
      org.opencontainers.image.licenses="AGPL-3.0-only"
ENTRYPOINT ["zpt-controller"]
CMD ["serve", "-db", "/data/controller.db", "-listen", ":8080"]
