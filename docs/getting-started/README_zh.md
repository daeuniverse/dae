# 吃鹅直通手册

## Linux 内核要求

### 内核版本

使用 `uname -r` 来查看内核版本。

> **注意**
> 如果你的内核版本低于 `5.8`，可以参考 [**Upgrade Guide**](./kernel-upgrade.md) 升级你的内核。

`绑定到 LAN 接口: >= 5.8`

如果你想作为路由器、网桥等中间设备，为其他设备提供代理服务，需要把 dae 绑定到 LAN 接口上。

该特性要求 dae 所在的设备的内核版本 >= 5.8。

如果你只在 `lan_interface` 中填写了接口，而未在 `wan_interface` 中填写内容，那么本地程序将无法被代理。如果你期望代理本地程序，需要在 `wan_interface` 中填写 `auto` 或是手动输入 WAN 接口。

`绑定到 WAN 接口: >= 5.8`

如果你想为本地程序提供代理服务，需要把 dae 绑定到 WAN 接口上。

该特性要求 dae 所在的设备的内核版本 >= 5.8。

如果你只在 `wan_interface` 中填写了接口或 `auto`，而未在 `lan_interface` 中填写内容，那么从局域网中传来的流量将无法被代理。如果你想同时代理本机和局域网流量，请同时填写 `wan_interface` 和 `lan_interface`。

## 内核配置选项

通常，主流桌面发行版都会打开这些选项。但是为了减小内核大小，在嵌入式设备发行版（如 OpenWRT、Armbian 等）上这些选项可能处于关闭状态。使用以下命令在你的设备上显示内核配置选项：

```shell
zcat /proc/config.gz || cat /boot/{config,config-$(uname -r)}
```

dae 需要以下内核选项：

```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_CGROUPS=y
CONFIG_KPROBES=y
CONFIG_NET_INGRESS=y
CONFIG_NET_EGRESS=y
CONFIG_NET_SCH_INGRESS=m
CONFIG_NET_CLS_BPF=m
CONFIG_NET_CLS_ACT=y
CONFIG_BPF_STREAM_PARSER=y
CONFIG_DEBUG_INFO=y
# CONFIG_DEBUG_INFO_REDUCED is not set
CONFIG_DEBUG_INFO_BTF=y
CONFIG_KPROBE_EVENTS=y
CONFIG_BPF_EVENTS=y
```

你可以通过以下命令检查他们：

```shell
(zcat /proc/config.gz || cat /boot/{config,config-$(uname -r)}) | grep -E 'CONFIG_(DEBUG_INFO|DEBUG_INFO_BTF|KPROBES|KPROBE_EVENTS|BPF|BPF_SYSCALL|BPF_JIT|BPF_STREAM_PARSER|NET_CLS_ACT|NET_SCH_INGRESS|NET_INGRESS|NET_EGRESS|NET_CLS_BPF|BPF_EVENTS|CGROUPS)=|# CONFIG_DEBUG_INFO_REDUCED is not set'
```

> **注意**: `Armbian` 用户可以参考 [**Upgrade Guide**](./kernel-upgrade.md) 升级到支持的内核。

## 安装

### Archlinux/Manjaro

dae 已发布于 [AUR](https://aur.archlinux.org/packages/dae)，使用下述命令安装：

```shell
# yay -S dae
pacman -S --needed git base-devel
git clone https://aur.archlinux.org/dae.git
cd dae
makepkg -si
```

安装后，使用 systemctl 对服务进行控制：

```shell
# 启动 dae
sudo systemctl start dae

# 开机自动启动 dae
sudo systemctl enable dae
```

### Gentoo Linux

dae 已发布于 [gentoo-zh](https://github.com/microcai/gentoo-zh)，可以使用 `app-eselect/eselect-repository` 启用此 overlay:

```shell
eselect repository enable gentoo-zh
emaint sync -r gentoo-zh
emerge -a net-proxy/dae
```

### macOS

我们提供了一种比较 hacky 的方式在 macOS 上运行 dae，见 [run on macOS](run-on-macos.md)。

## Run as daemon

dae 可以以守护进程（systemd）的形式运行，见 [run as daemon](run-as-daemon)。

### Docker

预编译镜像可相关文档请查阅：<https://hub.docker.com/r/daeuniverse/dae>。

作为替代，你也可以使用 `docker compose`:

```shell
git clone --depth=1 https://github.com/daeuniverse/dae
docker compose up -d --build
```

### 安装脚本

见 [daeuniverse/dae-installer](https://github.com/daeuniverse/dae-installer)（或使用 [镜像站](https://hubmirror.v2raya.org/daeuniverse/dae-installer)）。

### 手动构建

见 [Build Guide](build-by-yourself.md)。

## 最小 dae 配置

最小可启动的配置：

```shell
global{}
routing{}
```

然而，此配置使 dae 处于空载状态。如果你希望 dae 能正常工作，以下是较小配置下的最佳实践：

```shell
global {
  # 绑定到 LAN 和/或 WAN 接口。将下述接口替换成你自己的接口名。
  #lan_interface: docker0
  wan_interface: auto # 使用 "auto" 自动侦测 WAN 接口。

  log_level: info
  allow_insecure: false
  auto_config_kernel_parameter: true
}

subscription {
  # 在下面填入你的订阅链接。
}

# 更多的 DNS 样例见 https://github.com/daeuniverse/dae/blob/main/docs/dns.md
dns {
  upstream {
    googledns: 'tcp+udp://dns.google.com:53'
    alidns: 'udp://dns.alidns.com:53'
  }
  routing {
    request {
      fallback: alidns
    }
    response {
      upstream(googledns) -> accept
      !qname(geosite:cn) && ip(geoip:private) -> googledns
      fallback: accept
    }
  }
}

group {
  proxy {
    #filter: name(keyword: HK, keyword: SG)
    policy: min_moving_avg
  }
}

# 更多的 Routing 样例见 https://github.com/daeuniverse/dae/blob/main/docs/routing.md
routing {
  pname(NetworkManager, systemd-resolved, dnsmasq) -> must_direct
  dip(224.0.0.0/3, 'ff00::/8') -> direct

  ### 以下为自定义规则

  dip(geoip:private) -> direct
  dip(geoip:cn) -> direct
  domain(geosite:cn) -> direct

  fallback: proxy
}
```

如果你不在乎极致速度，而是更注重隐私和 DNS 泄露，使用以下配置替换上述的 dns 部分：

```shell
dns {
  upstream {
    googledns: 'tcp+udp://dns.google.com:53'
    alidns: 'udp://dns.alidns.com:53'
  }
  routing {
    request {
      qname(geosite:cn) -> alidns
      fallback: googledns
    }
  }
}
```

完整样例：[example.dae](https://github.com/daeuniverse/dae/blob/main/example.dae)。

如果你使用 PVE，可以参考 [#37](https://github.com/daeuniverse/dae/discussions/37)。

## 热重载和暂停

当配置变化时，可以方便使用命令进行配置的热重载，在该过程中不会中断已有连接。当想暂停代理时，可使用命令进行暂停。

详见 [Reload and suspend](reload-and-suspend.md)。

## 错误排查

详见 [Troubleshooting](troubleshooting.md)。

## 大鹅宇宙

Telegram: <https://t.me/daeuniverse>
