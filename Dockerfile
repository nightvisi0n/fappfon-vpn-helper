FROM golang:1.14-buster as BUILDER

WORKDIR /

RUN dpkg --add-architecture arm64 && \
    apt update && \
    apt -y install gcc-aarch64-linux-gnu libnetfilter-queue-dev:arm64 libnetfilter-queue1:arm64 && \
    apt clean

RUN mkdir /go/fappfon-vpn-helper

WORKDIR /go/fappfon-vpn-helper

COPY . .

RUN CC=aarch64-linux-gnu-gcc \
    CGO_ENABLED=1 \
    GOOS=linux \
    GOARCH=arm64 \
    PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig/ \
    CGO_LDFLAGS="-L/usr/lib/aarch64-linux-gnu -lnetfilter_queue" \
    go build .

FROM arm64v8/debian:buster

COPY --from=BUILDER /usr/lib/aarch64-linux-gnu/ /usr/lib/aarch64-linux-gnu/
COPY --from=BUILDER /go/fappfon-vpn-helper/fappfon-vpn-helper /fappfon-vpn-helper

ENTRYPOINT ["/fappfon-vpn-helper"]