# TODO: pin the base images by digest. `docker manifest inspect` and
# skopeo cannot reach registry-1.docker.io from the audit environment, so no
# digest is recorded here — do not invent one. Replace the tags below with
# `<repo>@sha256:<digest>` once a registry lookup is available.
FROM golang:1.26-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends llvm-15 clang-15 make \
    && rm -rf /var/lib/apt/lists/*
ENV CLANG=clang-15
WORKDIR /build/
ARG VERSION=unstable-docker
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN make OUTPUT=dae VERSION="${VERSION}" GOFLAGS="-buildvcs=false" CC=clang CGO_ENABLED=0

# TODO: same digest pin pending (the `alpine` tag is mutable).
FROM alpine

# Geo data is pinned by upstream release tag and verified with sha256sum -c.
# The ARG defaults are asserted against scripts/fetch-geo-data.sh by
# scripts/check-build-env.sh (that script is the single owner of the pins).
ARG GEOIP_VERSION=202609050329
ARG GEOIP_SHA256=1cba1f0982cf62502fa079c66047c3d0c608196da5b3305671e68f60e917a482
ARG GEOSITE_VERSION=20260908094002
ARG GEOSITE_SHA256=35ed26a24cafa1256bd7261414224b7bcef5c944cea7760e172b030a8b266450

RUN mkdir -p /usr/local/share/dae/
RUN mkdir -p /etc/dae/
RUN set -eux; \
    wget -O /usr/local/share/dae/geoip.dat "https://github.com/v2fly/geoip/releases/download/${GEOIP_VERSION}/geoip.dat"; \
    echo "${GEOIP_SHA256}  /usr/local/share/dae/geoip.dat" | sha256sum -c -; \
    wget -O /usr/local/share/dae/geosite.dat "https://github.com/v2fly/domain-list-community/releases/download/${GEOSITE_VERSION}/dlc.dat"; \
    echo "${GEOSITE_SHA256}  /usr/local/share/dae/geosite.dat" | sha256sum -c -
COPY --from=builder /build/dae /usr/local/bin
COPY --from=builder /build/install/empty.dae /etc/dae/config.dae
RUN chmod 0600 /etc/dae/config.dae

CMD ["dae"]
ENTRYPOINT ["dae", "run", "-c", "/etc/dae/config.dae"]
