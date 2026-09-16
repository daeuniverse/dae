# Quick Start Guide

[**简体中文**](../zh/README.md) | [**English**](README.md)

## Linux Kernel Requirements

### Kernel Version

Use `uname -r` to check the kernel version on your machine.

> **Note**
> If your kernel version is below 5.17, follow the [Upgrade Guide](user-guide/kernel-upgrade.md) to reach the minimum required version.

| Use case | Minimum kernel version | Traffic affected |
| --- | --- | --- |
| Bind to LAN | 5.17 | Traffic from LAN devices when dae acts as an intermediate device; local programs are unaffected if only LAN is bound. |
| Bind to WAN | 5.17 | Traffic from local programs; traffic arriving on other interfaces is unaffected if only WAN is bound. |
| Run `dae trace` | 5.15 | Network connectivity troubleshooting. |

The `trace` build tag is unavailable for `arm`, `mips`, `mips64`, `mips64le`,
`mipsle`, and `s390x` builds, so these builds do not include `dae trace`.
See the [Build Guide](user-guide/build-by-yourself.md#trace-support-per-architecture).

### Kernel Configurations

Mainstream desktop distributions usually enable the required options.
Distributions for embedded devices, such as OpenWrt and Armbian, disable some
of them by default to reduce kernel size.

Show your machine's kernel configuration:

```shell
zcat /proc/config.gz || cat /boot/{config,config-$(uname -r)}
```

dae requires:

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

Check the required options with the following commands.

For Bash and other POSIX-compliant shells:

```shell
(zcat /proc/config.gz || cat /boot/{config,config-$(uname -r)}) | grep -E 'CONFIG_(DEBUG_INFO|DEBUG_INFO_BTF|KPROBES|KPROBE_EVENTS|BPF|BPF_SYSCALL|BPF_JIT|BPF_STREAM_PARSER|NET_CLS_ACT|NET_SCH_INGRESS|NET_INGRESS|NET_EGRESS|NET_CLS_BPF|BPF_EVENTS|CGROUPS)=|# CONFIG_DEBUG_INFO_REDUCED is not set'
```

For fish:

```fish
begin; zcat /proc/config.gz || cat /boot/config "/boot/config-"(uname -r); end | grep -E 'CONFIG_(DEBUG_INFO|DEBUG_INFO_BTF|KPROBES|KPROBE_EVENTS|BPF|BPF_SYSCALL|BPF_JIT|BPF_STREAM_PARSER|NET_CLS_ACT|NET_SCH_INGRESS|NET_INGRESS|NET_EGRESS|NET_CLS_BPF|BPF_EVENTS|CGROUPS)=|# CONFIG_DEBUG_INFO_REDUCED is not set'
```

> **Note**: Armbian users can follow the [Upgrade Guide](user-guide/kernel-upgrade.md) to meet the kernel configuration requirements.
>
> Arch Linux ARM users can use [`linux-aarch64-7ji`](https://github.com/7Ji-PKGBUILDs/linux-aarch64-7ji), which meets dae's kernel configuration requirements.

## Installation

| System | Source | Section |
| --- | --- | --- |
| Debian / Ubuntu | Dae Universe APT repository | [Debian / Ubuntu](#debian--ubuntu) |
| Fedora / RHEL | Dae Universe RPM repository | [Fedora / RHEL](#fedora--rhel) |
| Fedora | Copr | [Fedora Copr](#fedora-copr) |
| openSUSE | Dae Universe RPM repository | [openSUSE](#opensuse) |
| Arch Linux | Official repository, AUR, archlinuxcn | [Arch Linux / Manjaro](#arch-linux--manjaro) |
| Manjaro | AUR / archlinuxcn | [Arch Linux / Manjaro](#arch-linux--manjaro) |
| Gentoo / Calculate | gentoo-zh overlay | [Gentoo Linux](#gentoo-linux) |
| Nix / NixOS | daeuniverse/flake.nix | [Nix / NixOS](#nix--nixos) |
| Alpine | dae-installer | [Alpine](#alpine) |
| macOS | Platform tutorial | [macOS](#macos) |
| Docker | Pre-built images or Docker Compose | [Docker](#docker) |
| Manual installation | Installation script or source build | [Manual Installation](#manual-installation) |

### Debian / Ubuntu

For Debian, Ubuntu, and other APT-based distributions, use the Dae Universe
repository at <https://daeuniverse.pages.dev>.
The commands below assume sudo is configured for your account.

#### 1. Install curl

```sh
sudo apt update
sudo apt install curl
```

#### 2. Add the APT Repository

Download the source configuration directly from the repository.
Choose one of the following alternatives to match your APT version.

For APT 3.0 or later:

```sh
sudo curl -fsSL -o /etc/apt/sources.list.d/daeuniverse.sources https://daeuniverse.pages.dev/daeuniverse.sources
```

For APT earlier than 3.0:

```sh
sudo curl -fsSL -o /etc/apt/sources.list.d/daeuniverse.list https://daeuniverse.pages.dev/daeuniverse.list
```

#### 3. Import the GPG Key

```sh
sudo curl -fsSL -o /usr/share/keyrings/daeuniverse-archive-goose.gpg https://daeuniverse.pages.dev/daeuniverse-archive-goose.gpg
```

#### 4. Install dae

```sh
sudo apt update
sudo apt install dae
```

The package includes a systemd service and an example at `/etc/dae/example.dae`.
Save your configuration as `/etc/dae/config.dae`.
Complete [Minimal Configuration](#minimal-configuration), then see
[Service Management](#service-management).

### Arch Linux / Manjaro

Install dae from the official repository, or choose an alternative package:

| Source | Packages |
| --- | --- |
| Official repository | dae |
| [AUR](https://aur.archlinux.org) | Latest AVX2-optimized binary package or latest Git version |
| [archlinuxcn](https://github.com/archlinuxcn/repo) | Latest AVX2-optimized binary package or latest Git version |

#### Official Repository

```shell
sudo pacman -S dae
```

#### AUR

##### Latest Release (Optimized Binary for x86-64 v3 / AVX2)

```shell
[yay/paru] -S dae-avx2-bin
```

##### Latest Git Version

```shell
[yay/paru] -S dae-git
```

#### archlinuxcn

##### Latest Release (Optimized Binary for x86-64 v3 / AVX2)

```shell
sudo pacman -S dae-avx2-bin
```

##### Latest Git Version

```shell
sudo pacman -S dae-git
```

After installation, manage dae with `systemctl`:

```shell
# start dae
sudo systemctl start dae

# auto start dae at boot
sudo systemctl enable dae
```

### Gentoo Linux

dae is available in the [gentoo-zh](https://github.com/microcai/gentoo-zh) overlay.
Enable the overlay with `app-eselect/eselect-repository`:

```shell
eselect repository enable gentoo-zh
emaint sync -r gentoo-zh
emerge -a net-proxy/dae
```

### Fedora / RHEL

#### Dae Universe RPM Repository

For Fedora and RHEL, use the Dae Universe repository at <https://daeuniverse.pages.dev>.
The commands below assume sudo is configured for your account.

##### 1. Add the DNF Repository

The repository configuration file includes the GPG key address.
DNF asks to import the key the first time it is used.

```sh
sudo curl -fsSL -o /etc/yum.repos.d/daeuniverse.repo https://daeuniverse.pages.dev/daeuniverse.repo
```

##### 2. Install dae

```sh
sudo dnf install dae
```

The package includes a systemd service and an example at `/etc/dae/example.dae`.
Save your configuration as `/etc/dae/config.dae`.
Complete [Minimal Configuration](#minimal-configuration), then see
[Service Management](#service-management).

#### Fedora Copr

For Fedora only, use [Fedora Copr](https://copr.fedorainfracloud.org/coprs/zhullyb/v2rayA/package/dae)
instead of the Dae Universe repository.
`zhullyb/v2rayA` is the Copr project name; the package installed is `dae`.

```shell
sudo dnf copr enable zhullyb/v2rayA
sudo dnf install dae
```

### openSUSE

Use the Dae Universe repository at <https://daeuniverse.pages.dev>.
The commands below assume sudo is configured for your account.

#### 1. Add the Zypper Repository

The repository configuration file includes the GPG key address.
Zypper asks whether to trust the key the first time it is used.

```sh
sudo curl -fsSL -o /etc/zypp/repos.d/daeuniverse.repo https://daeuniverse.pages.dev/daeuniverse.repo
```

#### 2. Install dae

```sh
sudo zypper install dae
```

The package includes a systemd service and an example at `/etc/dae/example.dae`.
Save your configuration as `/etc/dae/config.dae`.
Complete [Minimal Configuration](#minimal-configuration), then see
[Service Management](#service-management).

### Nix / NixOS

Use an existing NixOS flake configuration.
Retain your current Nixpkgs, system, and hardware modules.

#### 1. Import the NixOS Module

Replace `HOSTNAME` with your configuration name.
This example imports the dae module.

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

#### 2. Enable dae

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

Set exactly one of `configFile` and `config`.
To use an external file, add this option inside `services.dae` and prepare
the file before applying the configuration:

```nix
configFile = "/etc/dae/config.dae";
```

Inline `config` is readable by all users through the Nix store.
The firewall port must match `tproxy_port`.
See [Minimal Configuration](#minimal-configuration) and the
[dae module options](https://github.com/daeuniverse/flake.nix/blob/main/dae/module.nix).

#### 3. Apply the System Configuration

In the system flake directory, replace `HOSTNAME` and run:

```shell
sudo nixos-rebuild switch --flake .#HOSTNAME
```

The module manages systemd boot enablement; no separate `systemctl enable` is needed.

#### Alternative: Global Packages

Use this instead of the service module.
Do not install another dae through `environment.systemPackages` while enabling `services.dae`.
Replace `x86_64-linux` with `aarch64-linux` when appropriate.

```nix
# nixos configuration module
{
  environment.systemPackages =
    with inputs.daeuniverse.packages.x86_64-linux;
      [ dae ]; # or dae-unstable
}
```

#### Package Variants

| Package | Purpose |
| --- | --- |
| `dae` / `dae-release` | Release; `dae` aliases `dae-release` |
| `dae-unstable` | Tracks the dae main branch |

```shell
nix flake show github:daeuniverse/flake.nix
```

#### Optional: Binary Cache

The upstream garnix cache serves `x86_64-linux` and `aarch64-linux` builds.
Merge these settings into the NixOS configuration.

```nix
nix.settings = {
  substituters = ["https://cache.garnix.io"];
  trusted-public-keys = [
    "cache.garnix.io:CTFPyKSLcx5RMJKfLo5EEPUObbA78b0YQ2DTCJXqr9g="
  ];
};
```

See the [daeuniverse/flake.nix README](https://github.com/daeuniverse/flake.nix#readme).

### Alpine

See [Run on Alpine](tutorials/run-on-alpine.md).

### macOS

A workaround is available to run dae on macOS. See [Run on macOS](tutorials/run-on-macos.md).

### Docker

Pre-built images and documentation are available at <https://hub.docker.com/r/daeuniverse/dae>.

Alternatively, use `docker compose`:

```shell
git clone --depth=1 https://github.com/daeuniverse/dae
cd dae
docker compose up -d --build
```

## Manual Installation

> **Note**: Manual installation is recommended only for advanced users. It lets you test different dae versions, but new features may contain bugs. Proceed at your own risk.

To run dae as a systemd service, see [Run dae as a Daemon Service](user-guide/run-as-daemon.md).

### Installation Script

See [daeuniverse/dae-installer](https://github.com/daeuniverse/dae-installer) (or [mirror](https://hubmirror.v2raya.org/daeuniverse/dae-installer)).

### Build from Scratch

See [Build Guide](user-guide/build-by-yourself.md).

## Minimal Configuration

The smallest configuration that starts dae is:

```shell
global{}
routing{}
```

This configuration leaves dae idle. For a small working configuration, use:

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

If privacy and preventing DNS leaks matter more than maximum speed,
replace the `dns` section above with:

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

For more options, see [example.dae](https://github.com/daeuniverse/dae/blob/main/example.dae).

If you use PVE, refer to [#37](https://github.com/daeuniverse/dae/discussions/37).

## Service Management

For systemd installations, complete [Minimal Configuration](#minimal-configuration)
first, then choose the action you need.
Enabling the service at boot does not start it immediately.

| Action | Command |
| --- | --- |
| Start now | `sudo systemctl start dae` |
| Enable at boot | `sudo systemctl enable dae` |

## PPPoE Interface

To proxy a PPPoE interface, set `wan_interface` or `lan_interface` to the
interface created by pppd (such as `ppp0` or `pppoe-wan`), not the physical interface.
If you use PPPoE only for WAN, set `wan_interface` to `auto`.

## Reload and Suspend

Reload the configuration without interrupting existing connections, or suspend dae temporarily.

See [Reload and suspend](user-guide/reload-and-suspend.md).

## Troubleshooting

See [Troubleshooting](troubleshooting.md).
