# 升级内核

Linux 是内核，而非完整的操作系统。内核是操作系统的核心。

## 各发行版的内核升级方法

### 免责声明

升级 Linux 内核并不简单。只有遇到安全缺陷或硬件交互问题时，才必须升级。如果系统崩溃，可能需要恢复整个系统。

多数 Linux 发行版已随附最新内核。升级内核不会删除旧内核，旧内核仍保留在系统中。

> **注意**：除非需要特定驱动支持，否则不应手动升级内核；硬件或安全问题也可能需要升级。可从系统恢复菜单回滚到旧内核。

### 准备工作

升级前，执行 `uname -r` 检查主机当前运行的内核版本。此处 eBPF 的最低版本要求为 `>= 5.17`。

各发行版的升级方法不同。本页覆盖 Armbian、Debian 及其衍生发行版、Red Hat、Fedora 及其衍生发行版，以及 Arch 及其衍生发行版。

> **注意**：由于 dae 基于 eBPF 构建，主机内核版本必须 >= 5.17，dae 才能正常运行。

### 在 Armbian Linux 上升级到 BTF 内核

Armbian 用户可使用已编译并启用 BTF 的内核，参见 [daeuniverse/armbian-btf-kernel](https://github.com/daeuniverse/armbian-btf-kernel)。

### 在基于 Debian 的 Linux 上升级内核

Armbian 等 Debian 衍生发行版可用以下命令安装指定版本的内核：

```shell
# Sync databases.
sudo apt update
# Search available kernel versions.
apt-cache search ^linux-image
# Install specific image.
sudo apt install <specific-linux-image>
```

安装完成后，重启系统以使用新内核，再检查内核版本：

```shell
sudo reboot
uname -r
```

以下升级到最新内核的方法仅适用于 Debian，属于激进升级：

> **警告**：Debian 官方支持的最新内核位于 `unstable`。Debian Unstable 的代号为 SID，是持续滚动的开发版本，而非正式发行版，包含新引入 Debian 的软件包。升级可能带来破坏性变更，使用者需自行承担风险。

参考资料：[在 Debian 11 上安装 Linux 5.14 内核](https://www.itsfoss.net/installing-linux-5-14-kernel-on-debian-11)。

> **注意**：如果系统不是 Debian 11，请修改 `Pin: release a=bullseye`。例如，Debian 10 使用 `Pin: release a=buster`。

```shell
# Add unstable source
cat <<EOF | sudo tee /etc/apt/sources.list.d/unstable.list
deb http://deb.debian.org/debian unstable main contrib non-free
deb-src http://deb.debian.org/debian unstable main contrib non-free
EOF

# Create apt preferences
cat <<EOF | sudo tee /etc/apt/preferences
Package: *
Pin: release a=bullseye
Pin-Priority: 500

Package: linux-image-amd64
Pin: release a=unstable
Pin-Priority: 1000

Package: *
Pin: release a=unstable
Pin-Priority: 100
EOF

# Sync databases, including the source added above.
sudo apt update
# Perform full dist-upgrade
sudo apt dist-upgrade
```

重启系统以使用新内核，再检查内核版本：

```shell
sudo reboot
uname -r
```

### 在 Red Hat 和 Fedora Linux 上升级内核

Fedora、Red Hat 及其衍生发行版可从仓库下载内核，手动升级到指定版本。安装命令如下：

```bash
sudo yum install kernel
```

安装完成后，重启系统以使用新内核，再检查内核版本：

```bash
sudo reboot
uname -r
```

### 在基于 Arch 的 Linux 上升级内核

Arch 及其衍生发行版提供多种持续更新的 Linux 内核。Arch Linux 定期更新安全补丁，因此经常有内核和补丁更新可用。

Manjaro 及其他 Arch 衍生发行版通常通过更新管理器提供内核更新。系统更新程序会检查最新内核，也可使用以下 `pacman` 命令检查：

```bash
# Search available kernel images.
pacman -Ss ^linux$
# Install specific kernel image.
pacman -S <specific-linux-image>
```

确认安装并等待完成后，重启系统，再检查内核版本以确认升级结果：

```bash
sudo reboot
uname -r
```
