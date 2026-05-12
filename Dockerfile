FROM golang:1.23-alpine3.21 AS builder

RUN apk add --no-cache alpine-sdk ca-certificates

ARG VERSION

ENV CGO_ENABLED=0 \
    GO111MODULE=on \
    LDFLAGS="-X github.com/R4MT1N/kafka-gcp-proxy/config.Version=${VERSION} -w -s"

WORKDIR /go/src/github.com/R4MT1N/kafka-gcp-proxy
COPY . .

RUN mkdir -p build && \
    go build -mod=vendor -o build/kafka-gcp-proxy -ldflags "${LDFLAGS}" .

FROM alpine:3.21

RUN apk add --no-cache ca-certificates libcap && \
    adduser --disabled-password --gecos "" \
            --home "/nonexistent" --shell "/sbin/nologin" \
            --no-create-home kafka-gcp-proxy

COPY --from=builder /go/src/github.com/R4MT1N/kafka-gcp-proxy/build /opt/kafka-gcp-proxy/bin
RUN setcap 'cap_net_bind_service=+ep' /opt/kafka-gcp-proxy/bin/kafka-gcp-proxy

USER kafka-gcp-proxy
ENTRYPOINT ["/opt/kafka-gcp-proxy/bin/kafka-gcp-proxy"]
CMD ["--help"]
