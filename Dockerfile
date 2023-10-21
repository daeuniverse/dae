FROM golang:1.21-bookworm AS builder
RUN apt-get update && apt-get install -y llvm-15 clang-15 git make
ENV CLANG=clang-15
WORKDIR /build/
ADD go.mod go.sum ./
RUN go mod download
ADD . .
RUN git submodule update --init
RUN make OUTPUT=dae GOFLAGS="-buildvcs=false" CC=clang CGO_ENABLED=0

FROM alpine
RUN mkdir -p /usr/local/share/dae/
RUN mkdir -p /etc/dae/
RUN wget -O /usr/local/share/dae/geoip.dat https://github.com/v2fly/geoip/releases/latest/download/geoip.dat
RUN wget -O /usr/local/share/dae/geosite.dat https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat
COPY --from=builder /build/dae /usr/local/bin
COPY --from=builder /build/install/empty.dae /etc/dae/config.dae
RUN chmod 0600 /etc/dae/config.dae

CMD ["dae"]
ENTRYPOINT ["dae", "run", "-c", "/etc/dae/config.dae"]
