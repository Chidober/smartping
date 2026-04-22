# SmartPing expects the binary at <root>/bin/smartping so GetRoot() resolves to <root>.
FROM golang:1.22-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libc6-dev libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

ENV GOPATH=/go CGO_ENABLED=1
WORKDIR /go/src/github.com/smartping/smartping

COPY . .
# Pin golang.org/x/* so tidy does not pull releases that require a newer Go toolchain.
RUN go mod init github.com/smartping/smartping \
    && go get golang.org/x/net@v0.21.0 golang.org/x/image@v0.14.0 \
    && go mod tidy \
    && go build -ldflags="-s -w" -o /smartping src/smartping.go

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /app/bin /app/conf /app/db /app/html /seed/db
COPY --from=builder /smartping /app/bin/smartping
COPY conf/ /app/conf/
COPY html/ /app/html/
COPY db/ /seed/db/
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

WORKDIR /app
EXPOSE 8899

# Raw ICMP sockets need elevated network capability (see docker-compose).
USER root

ENTRYPOINT ["/docker-entrypoint.sh"]
