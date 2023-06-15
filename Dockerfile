FROM golang:1.20-bullseye AS builder
RUN apt-get update && apt-get install -y llvm clang git make
WORKDIR /build/
ADD go.mod go.sum ./
RUN go mod download
ADD . .
RUN git submodule update --init
RUN make OUTPUT=dae GOFLAGS="-buildvcs=false" CC=clang CGO_ENABLED=0

FROM alpine
RUN mkdir -p /usr/local/share/dae/
RUN mkdir -p /etc/dae/
RUN wget -O /usr/local/share/dae/geoip.dat https://github.com/v2rayA/dist-v2ray-rules-dat/raw/master/geoip.dat
RUN wget -O /usr/local/share/dae/geosite.dat https://github.com/v2rayA/dist-v2ray-rules-dat/raw/master/geosite.dat
COPY --from=builder /build/dae /usr/local/bin
COPY --from=builder /build/install/empty.dae /etc/dae/config.dae
RUN chmod 0600 /etc/dae/config.dae

CMD ["dae"]
ENTRYPOINT ["dae", "run", "-c", "/etc/dae/config.dae"]
