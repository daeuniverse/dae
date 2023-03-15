# Build Guide

## Build

**Make Dependencies**

```shell
clang >= 10
llvm >= 10
golang >= 1.18
make
```

**Build**

```shell
git clone https://github.com/daeuniverse/dae.git
cd dae
git submodule update --init
# Minimal dependency build:
make GOFLAGS="-buildvcs=false" CC=clang
# Or normal build:
# make
```

## Run

**Runtime Dependencies**

For traffic splitting, dae relies on the following data sources, [geoip.dat](https://github.com/v2ray/geoip/releases/latest) and [geosite.dat](https://github.com/v2fly/domain-list-community/releases/latest).

```shell
mkdir -p /usr/local/share/dae/
pushd /usr/local/share/dae/
curl -L -o geoip.dat https://github.com/v2ray/geoip/releases/latest/download/geoip.dat
curl -L -o geosite.dat https://github.com/v2ray/domain-list-community/releases/latest/download/dlc.dat
popd
```

**Run**

Download the example config file:
```shell
curl -L -o example.dae https://github.com/daeuniverse/dae/raw/main/example.dae
```
See [example.dae](https://github.com/daeuniverse/dae/blob/main/example.dae).

After fine tuning, run dae:
```shell
./dae run -c example.dae
```

Alternatively, you may run dae as a daemon(systemd) service. Check out more details [HERE](./run-as-daemon.md).