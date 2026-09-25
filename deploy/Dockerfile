# Контроллер zeropentime: админ-панель + API для узлов.
# Сборка из корня репозитория:  docker build -f deploy/Dockerfile -t zeropentime .
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /zpt ./cmd/zpt

FROM alpine:3.22
RUN apk add --no-cache ca-certificates && adduser -D -H -u 10001 zpt && mkdir /data && chown zpt /data
COPY --from=build /zpt /usr/local/bin/zpt
USER zpt
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["zpt", "controller"]
CMD ["serve", "-db", "/data/controller.db", "-listen", ":8080"]
