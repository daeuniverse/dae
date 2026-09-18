# 快速入门

[**简体中文**](README.md) | [**English**](../en/README.md)

## Linux 内核要求

### 内核版本

使用 `uname -r` 检查计算机上的内核版本。

> **注意**：内核版本低于 `5.17` 时，请按照[升级指南](user-guide/kernel-upgrade.md)升级到最低要求版本。

| 使用方式 | 最低内核版本 | 用途与影响范围 |
| --- | --- | --- |
| 绑定到 LAN | `5.17` | 作为中间设备为 LAN 提供网络服务。仅绑定 LAN 时，只处理来自 LAN 的流量，不影响本地程序。 |
| 绑定到 WAN | `5.17` | 为本地程序提供网络服务。仅绑定 WAN 时，不影响从其他接口进入的流量。 |
| `dae trace` | `5.15` | 排查网络连通性问题。 |

`arm`、`mips`、`mips64`、`mips64le`、`mipsle` 和 `s390x` 架构的构建不支持 `trace` 构建标签，因此不提供 `dae trace` 命令。详见[构建指南](user-guide/build-by-yourself.md#各架构的-trace-支持)。

### 内核配置

主流桌面发行版通常会启用所需配置项。OpenWRT、Armbian 等嵌入式设备发行版为了减小内核体积，默认会关闭部分配置项。

使用以下命令查看计算机上的内核配置：

```shell
zcat /proc/config.gz || cat /boot/{config,config-$(uname -r)}
```

dae 需要以下配置项：

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

使用以下命令检查这些配置项。

Bash 和其他兼容 POSIX 的 shell：

```shell
(zcat /proc/config.gz || cat /boot/{config,config-$(uname -r)}) | grep -E 'CONFIG_(DEBUG_INFO|DEBUG_INFO_BTF|KPROBES|KPROBE_EVENTS|BPF|BPF_SYSCALL|BPF_JIT|BPF_STREAM_PARSER|NET_CLS_ACT|NET_SCH_INGRESS|NET_INGRESS|NET_EGRESS|NET_CLS_BPF|BPF_EVENTS|CGROUPS)=|# CONFIG_DEBUG_INFO_REDUCED is not set'
```

fish shell：

```fish
begin; zcat /proc/config.gz || cat /boot/config "/boot/config-"(uname -r); end | grep -E 'CONFIG_(DEBUG_INFO|DEBUG_INFO_BTF|KPROBES|KPROBE_EVENTS|BPF|BPF_SYSCALL|BPF_JIT|BPF_STREAM_PARSER|NET_CLS_ACT|NET_SCH_INGRESS|NET_INGRESS|NET_EGRESS|NET_CLS_BPF|BPF_EVENTS|CGROUPS)=|# CONFIG_DEBUG_INFO_REDUCED is not set'
```

> **注意**：Armbian 用户可按照[升级指南](user-guide/kernel-upgrade.md)升级内核，以满足配置要求。
>
> Arch Linux ARM 用户可使用满足 dae 内核配置要求的 [`linux-aarch64-7ji`](https://github.com/7Ji-PKGBUILDs/linux-aarch64-7ji)。

## 安装

| 系统 | 来源 | 章节 |
| --- | --- | --- |
| Debian / Ubuntu | Dae Universe APT 软件源 | [Debian / Ubuntu](#debian--ubuntu) |
| Fedora / RHEL | Dae Universe RPM 软件源 | [Fedora / RHEL](#fedora--rhel) |
| Fedora | Copr | [Fedora Copr](#fedora-copr) |
| openSUSE | Dae Universe RPM 软件源 | [openSUSE](#opensuse) |
| Arch Linux | 官方仓库、AUR、archlinuxcn | [Arch Linux / Manjaro](#arch-linux--manjaro) |
| Manjaro | AUR / archlinuxcn | [Arch Linux / Manjaro](#arch-linux--manjaro) |
| Gentoo / Calculate | gentoo-zh overlay | [Gentoo Linux](#gentoo-linux) |
| Nix / NixOS | daeuniverse/flake.nix | [Nix / NixOS](#nix--nixos) |
| Alpine | dae-installer | [Alpine](#alpine) |
| macOS | 平台教程 | [macOS](#macos) |
| Docker | 预构建镜像或 Docker Compose | [Docker](#docker) |
| 手动安装 | 安装脚本或从源码构建 | [手动安装](#手动安装) |

### Debian / Ubuntu

Debian、Ubuntu 及其他使用 APT 的发行版可使用 <https://daeuniverse.pages.dev> 提供的 Dae Universe 软件源。
以下命令假定已为当前账户配置 sudo。

#### 1. 安装 curl

```sh
sudo apt update
sudo apt install curl
```

#### 2. 添加 APT 软件源

直接从软件源下载源配置文件。
根据 APT 版本，选择以下一种方式。

APT 3.0 及以上版本：

```sh
sudo curl -fsSL -o /etc/apt/sources.list.d/daeuniverse.sources https://daeuniverse.pages.dev/daeuniverse.sources
```

APT 3.0 之前的版本：

```sh
sudo curl -fsSL -o /etc/apt/sources.list.d/daeuniverse.list https://daeuniverse.pages.dev/daeuniverse.list
```

#### 3. 导入 GPG 密钥

```sh
sudo curl -fsSL -o /usr/share/keyrings/daeuniverse-archive-goose.gpg https://daeuniverse.pages.dev/daeuniverse-archive-goose.gpg
```

#### 4. 安装 dae

```sh
sudo apt update
sudo apt install dae
```

软件包包含 systemd 服务和示例文件 `/etc/dae/example.dae`。
将配置保存为 `/etc/dae/config.dae`。
完成[最小配置](#最小配置)后，参见[服务管理](#服务管理)。

### Arch Linux / Manjaro

可以直接从官方仓库安装 dae，也可从 [AUR](https://aur.archlinux.org) 或 [archlinuxcn](https://github.com/archlinuxcn/repo) 获取最新的 AVX2 优化二进制软件包或最新 Git 版本。

| 来源 | 软件包 |
| --- | --- |
| 官方仓库 | dae |
| [AUR](https://aur.archlinux.org) | 最新的 AVX2 优化二进制软件包或最新 Git 版本 |
| [archlinuxcn](https://github.com/archlinuxcn/repo) | 最新的 AVX2 优化二进制软件包或最新 Git 版本 |

#### 官方仓库

```shell
sudo pacman -S dae
```

#### AUR

##### 最新发行版（针对 x86-64 v3 / AVX2 优化）

```shell
[yay/paru] -S dae-avx2-bin
```

##### 最新 Git 版本

```shell
[yay/paru] -S dae-git
```

#### archlinuxcn

##### 最新发行版（针对 x86-64 v3 / AVX2 优化）

```shell
sudo pacman -S dae-avx2-bin
```

##### 最新 Git 版本

```shell
sudo pacman -S dae-git
```

安装后，使用 `systemctl` 管理服务：

```shell
# start dae
sudo systemctl start dae

# auto start dae at boot
sudo systemctl enable dae
```

### Gentoo Linux

dae 已发布于 [gentoo-zh](https://github.com/microcai/gentoo-zh)。使用 `app-eselect/eselect-repository` 启用此 overlay：

```shell
eselect repository enable gentoo-zh
emaint sync -r gentoo-zh
emerge -a net-proxy/dae
```

### Fedora / RHEL

#### Dae Universe RPM 软件源

Fedora 和 RHEL 可使用 <https://daeuniverse.pages.dev> 提供的 Dae Universe 软件源。
以下命令假定已为当前账户配置 sudo。

##### 1. 添加 DNF 软件源

软件源配置文件包含 GPG 密钥地址。
DNF 首次使用该软件源时会询问是否导入密钥。

```sh
sudo curl -fsSL -o /etc/yum.repos.d/daeuniverse.repo https://daeuniverse.pages.dev/daeuniverse.repo
```

##### 2. 安装 dae

```sh
sudo dnf install dae
```

软件包包含 systemd 服务和示例文件 `/etc/dae/example.dae`。
将配置保存为 `/etc/dae/config.dae`。
完成[最小配置](#最小配置)后，参见[服务管理](#服务管理)。

#### Fedora Copr

dae 已发布于 [Fedora Copr](https://copr.fedorainfracloud.org/coprs/zhullyb/v2rayA/package/dae)。
此方式仅适用于 Fedora，可替代 Dae Universe 软件源。
`zhullyb/v2rayA` 是 Copr 项目名，安装的软件包为 `dae`。

```shell
sudo dnf copr enable zhullyb/v2rayA
sudo dnf install dae
```

### openSUSE

使用 <https://daeuniverse.pages.dev> 提供的 Dae Universe 软件源。
以下命令假定已为当前账户配置 sudo。

#### 1. 添加 Zypper 软件源

软件源配置文件包含 GPG 密钥地址。
Zypper 首次使用该软件源时会询问是否信任密钥。

```sh
sudo curl -fsSL -o /etc/zypp/repos.d/daeuniverse.repo https://daeuniverse.pages.dev/daeuniverse.repo
```

#### 2. 安装 dae

```sh
sudo zypper install dae
```

软件包包含 systemd 服务和示例文件 `/etc/dae/example.dae`。
将配置保存为 `/etc/dae/config.dae`。
完成[最小配置](#最小配置)后，参见[服务管理](#服务管理)。

### Nix / NixOS

使用现有的 NixOS flake 配置。
保留当前的 Nixpkgs、系统模块和硬件模块。

#### 1. 导入 NixOS 模块

将 `HOSTNAME` 替换为配置名称。
以下示例导入 dae 模块。

```nix
# flake.nix

{
  inputs.daeuniverse.url = "github:daeuniverse/flake.nix";
  # ...

  outputs = {nixpkgs, ...} @ inputs: {
    nixosConfigurations.HOSTNAME = nixpkgs.lib.nixosSystem {
      modules = [
        inputs.daeuniverse.nixosModules.dae
      ];
    };
  };
}
```

#### 2. 启用 dae

```nix
# nixos configuration module
{
  # ...

  services.dae = {
      enable = true;

      openFirewall = {
        enable = true;
        port = 12345;
      };

      # `configFile` or `config` must be set

      /* default options

      package = inputs.daeuniverse.packages.x86_64-linux.dae;
      disableTxChecksumIpGeneric = false;
      assets = with pkgs; [ v2ray-geoip v2ray-domain-list-community ];

      */

      # alternative of `assets`, a dir contains geo database.
      # assetsPath = "/etc/dae";
  };
}
```

`configFile` 和 `config` 必须且只能设置其中一项。
如需使用外部文件，在 `services.dae` 内添加以下选项，并在应用配置前准备好该文件：

```nix
configFile = "/etc/dae/config.dae";
```

所有用户都能通过 Nix store 读取内联的 `config`。
防火墙端口必须与 `tproxy_port` 一致。
参见[最小配置](#最小配置)和 [dae 模块选项](https://github.com/daeuniverse/flake.nix/blob/main/dae/module.nix)。

#### 3. 应用系统配置

在系统 flake 目录中，替换 `HOSTNAME` 后执行：

```shell
sudo nixos-rebuild switch --flake .#HOSTNAME
```

模块会管理 systemd 开机启动设置，无需另行执行 `systemctl enable`。

#### 替代方式：全局软件包

此方式可替代服务模块。
启用 `services.dae` 时，不要再通过 `environment.systemPackages` 安装另一个 dae。
按需将 `x86_64-linux` 替换为 `aarch64-linux`。

```nix
# nixos configuration module
{
  environment.systemPackages =
    with inputs.daeuniverse.packages.x86_64-linux;
      [ dae ]; # or dae-unstable
}
```

#### 软件包变体

| 软件包 | 用途 |
| --- | --- |
| `dae` / `dae-release` | 发行版；`dae` 是 `dae-release` 的别名 |
| `dae-unstable` | 跟踪 dae 主分支 |

```shell
nix flake show github:daeuniverse/flake.nix
```

#### 可选：二进制缓存

上游 garnix 缓存提供 `x86_64-linux` 和 `aarch64-linux` 架构的构建。
将以下设置合并到 NixOS 配置中。

```nix
nix.settings = {
  substituters = ["https://cache.garnix.io"];
  trusted-public-keys = [
    "cache.garnix.io:CTFPyKSLcx5RMJKfLo5EEPUObbA78b0YQ2DTCJXqr9g="
  ];
};
```

参见 [daeuniverse/flake.nix README](https://github.com/daeuniverse/flake.nix#readme)。

### Alpine

参见[在 Alpine 上运行](tutorials/run-on-alpine.md)。

### macOS

可通过变通方案在 macOS 上运行 dae，参见[在 macOS 上运行](tutorials/run-on-macos.md)。

### Docker

预构建镜像及相关文档位于 <https://hub.docker.com/r/daeuniverse/dae>。

也可以使用 `docker compose`：

```shell
git clone --depth=1 https://github.com/daeuniverse/dae
cd dae
docker compose up -d --build
```

## 手动安装

> **注意**：手动安装仅建议有经验的用户使用，便于测试不同版本的 dae。新功能有时存在缺陷，使用者需自行承担风险。

dae 可以作为 systemd 守护进程运行，参见[作为守护进程运行](user-guide/run-as-daemon.md)。

### 安装脚本

参见 [daeuniverse/dae-installer](https://github.com/daeuniverse/dae-installer)（或[镜像](https://hubmirror.v2raya.org/daeuniverse/dae-installer)）。

### 从源码构建

参见[构建指南](user-guide/build-by-yourself.md)。

## 最小配置

以下是最小可启动配置：

```shell
global{}
routing{}
```

此配置会使 dae 处于无负载状态。要让 dae 处理流量，可使用以下精简配置：

```shell
global {
  # Bind to LAN and/or WAN as you want. Replace the interface name to your own.
  #lan_interface: docker0
  wan_interface: auto # Use "auto" to auto detect WAN interface.

  log_level: info
  allow_insecure: false
  auto_config_kernel_parameter: true
}

subscription {
  # Fill in your subscription links here.
}

# See https://github.com/daeuniverse/dae/blob/main/docs/en/configuration/dns.md for full examples.
dns {
  upstream {
    googledns: 'tcp+udp://dns.google:53'
    alidns: 'udp://dns.alidns.com:53'
  }
  routing {
    request {
      qtype(https) -> reject
      fallback: alidns
    }
    response {
      upstream(googledns) -> accept
      ip(geoip:private) && !qname(geosite:cn) -> googledns
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

# See https://github.com/daeuniverse/dae/blob/main/docs/en/configuration/routing.md for full examples.
routing {
  pname(NetworkManager) -> direct
  dip(224.0.0.0/3, 'ff00::/8') -> direct

  ### Write your rules below.

  # Disable h3 because it usually consumes too much cpu/mem resources.
  l4proto(udp) && dport(443) -> block
  dip(geoip:private) -> direct
  dip(geoip:cn) -> direct
  domain(geosite:cn) -> direct

  fallback: proxy
}
```

如果相比极致速度，更重视隐私和防止 DNS 泄漏，请将上面的 `dns` 部分替换为：

```shell
dns {
  upstream {
    googledns: 'tcp+udp://dns.google:53'
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

更多内容参见 [example.dae](https://github.com/daeuniverse/dae/blob/main/example.dae)。

如果使用 PVE，请参见 [#37](https://github.com/daeuniverse/dae/discussions/37)。

## 服务管理

通过 systemd 安装时，先完成[最小配置](#最小配置)，再选择所需操作。
设置开机启动不会立即启动服务。

| 操作 | 命令 |
| --- | --- |
| 立即启动 | `sudo systemctl start dae` |
| 开机启动 | `sudo systemctl enable dae` |

## PPPoE 接口

代理 PPPoE 接口时，请将 `wan_interface` 或 `lan_interface` 设为 pppd 生成的接口（`ppp0` / `pppoe-wan`），而非物理接口。

如果 PPPoE 接口仅用于 WAN，将 `wan_interface` 设为 `auto` 即可。

## 重载与暂停

配置变更后，可通过命令热重载配置，不会中断现有连接。需要暂停 dae 时，也可使用命令操作。

参见[重载与暂停](user-guide/reload-and-suspend.md)。

## 故障排查

参见[故障排查](troubleshooting.md)。
