# Build Guide

## Build

### Make Dependencies

```shell
clang >= 10
llvm >= 10 (optional)
golang >= 1.26
make
```

### Compilation

```shell
git clone https://github.com/daeuniverse/dae.git
cd dae
git submodule update --init
## Minimal dependency build
make GOFLAGS="-buildvcs=false" \
  CC=clang

## Normal build
#make

## Cross compile
# To armv7 CPU architect:
#make CGO_ENABLED=0 GOARCH=arm GOARM=7
# To mips CPU architect:
#make CGO_ENABLED=0 GOARCH=mips
```

### Trace support per architecture

`make` builds the optional `dae trace` eBPF program when the toolchain can
generate it and records the result in `.build_tags` (`trace`, or empty when the
build ran without it). **`arm`, `mips`, `mips64`, `mips64le`, `mipsle` and `s390x` do not
get `dae trace`** (`TRACE_UNSUPPORTED_GOARCH` in the Makefile): for those the build
prints a `WARNING`, produces a binary without the `trace` build tag and
continues. For every other `GOARCH` a failed trace generation is an error, so a
binary cannot lose `dae trace` silently.

The list is a measured claim, not an assumption, and it is re-verified by
`./scripts/check-trace-arch-matrix.sh` in the BPF Test workflow. Reproduce it
per architecture with:

```shell
git submodule update --init
GOARCH=mips BPF_CLANG=clang go generate ./trace/trace.go    # fails: no compiler specified
GOARCH=mips64 BPF_CLANG=clang go generate ./trace/trace.go  # fails: unsupported target
```

Do not remove an architecture from the list because
`github.com/cilium/ebpf`'s `gen.FindTarget()` accepts it: target lookup and
compilation are different steps, and `mips` passes the former while failing the
latter (its `bpf_tracing.h` selects the mips `pt_regs` layout while the vendored
`vmlinux.h` from the `dae_bpf_headers` submodule falls back to x86).

`dae trace` itself needs a kernel >= 5.15; the rest of dae needs >= 5.17.

## Run

### Runtime Dependencies

For traffic splitting, dae relies on the following data sources, [geoip.dat](https://github.com/v2fly/geoip/releases/latest) and [geosite.dat](https://github.com/v2fly/domain-list-community/releases/latest).

```shell
mkdir -p /usr/local/share/dae/
pushd /usr/local/share/dae/
curl -L -o geoip.dat https://github.com/v2fly/geoip/releases/latest/download/geoip.dat
curl -L -o geosite.dat https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat
popd
```

### Run

Download the example config file:

```shell
curl -L -o example.dae https://github.com/daeuniverse/dae/raw/main/example.dae
```

See [example.dae](https://github.com/daeuniverse/dae/blob/main/example.dae).

After fine tuning, run dae:

```shell
./dae run -c example.dae
```

> **Note**: Alternatively, you may run dae as a daemon (systemd) service. Check out more details [HERE](run-as-daemon.md).
