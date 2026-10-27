# 从源码构建

## 构建

### 构建依赖

```shell
clang >= 10
llvm >= 10 (optional)
golang >= 1.26
make
```

### 编译

```shell
git clone https://github.com/daeuniverse/dae.git
cd dae
git submodule update --init
## Minimal dependency build
make GOFLAGS="-buildvcs=false" \
  CLANG=clang

## Normal build
#make

## Cross compile
# To armv7 CPU architect:
#make CGO_ENABLED=0 GOARCH=arm GOARM=7
# To mips CPU architect:
#make CGO_ENABLED=0 GOARCH=mips
```

### 完整源码归档

完整源码归档包含 Git 子模块和 `go-mod/` 缓存，Makefile 会自动使用。安装构建工具链后可离线编译：

```shell
make GOFLAGS="-buildvcs=false" GOPROXY=off GOSUMDB=off
```

### 各架构的 trace 支持

当工具链能够生成可选的 `dae trace` eBPF 程序时，`make` 会将其构建进二进制文件。结果记录在 `.build_tags` 中：包含该程序时为 `trace`，未包含时为空。

| 目标架构 | trace 构建行为 |
| --- | --- |
| `arm`、`mips`、`mips64`、`mips64le`、`mipsle`、`s390x` | Makefile 的 `TRACE_UNSUPPORTED_GOARCH` 将这些架构列为不支持；构建时输出 `WARNING`，继续生成不带 `trace` 构建标签的二进制文件 |
| 其他 `GOARCH` | trace 生成失败会报错，不会在没有提示的情况下生成缺少 `dae trace` 的二进制文件 |

该列表基于实际验证，而非推测；BPF Test 工作流会通过 `./scripts/check-trace-arch-matrix.sh` 重新验证。可用以下命令按架构复现：

```shell
git submodule update --init
GOARCH=mips BPF_CLANG=clang go generate ./trace/trace.go    # fails: no compiler specified
GOARCH=mips64 BPF_CLANG=clang go generate ./trace/trace.go  # fails: unsupported target
```

不要仅因 `github.com/cilium/ebpf` 的 `gen.FindTarget()` 接受某个架构，就将其从列表中移除。目标查找与编译是不同的步骤：`mips` 能通过前者，却无法通过后者。原因是 `bpf_tracing.h` 选择了 mips 的 `pt_regs` 布局，而 `dae_bpf_headers` 子模块提供的 `vmlinux.h` 则回退到 x86。

`dae trace` 本身要求内核版本 >= 5.15；dae 的其余功能要求内核版本 >= 5.17。

## 运行

### 运行时依赖

dae 使用 [geoip.dat](https://github.com/v2fly/geoip/releases/latest) 和 [geosite.dat](https://github.com/v2fly/domain-list-community/releases/latest) 数据进行流量分流。

```shell
mkdir -p /usr/local/share/dae/
pushd /usr/local/share/dae/
curl -L -o geoip.dat https://github.com/v2fly/geoip/releases/latest/download/geoip.dat
curl -L -o geosite.dat https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat
popd
```

### 运行

下载示例配置文件：

```shell
curl -L -o example.dae https://github.com/daeuniverse/dae/raw/main/example.dae
```

请参阅 [example.dae](https://github.com/daeuniverse/dae/blob/main/example.dae)。

调整配置后，运行 dae：

```shell
./dae run -c example.dae
```

> **注意**：也可将 dae 作为 systemd 守护进程运行，参见[守护进程服务指南](run-as-daemon.md)。
