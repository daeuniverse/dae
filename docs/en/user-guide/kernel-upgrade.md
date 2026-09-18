# Kernel Upgrade Guide

Linux is a kernel, the core of an operating system, rather than a complete operating system.

## How to Upgrade the Linux Kernel on Various Distributions

### Disclaimer

Upgrade the Linux kernel only to address security or hardware issues. If the
system crashes, you may need to recover the whole system. Most Linux
distributions ship an up-to-date kernel. Upgrading keeps the previous kernel.

> **Note**: Do not upgrade the kernel manually unless you need specific driver support. Hardware or security issues may require an upgrade. You can roll back to the older kernel from your system's recovery menu.

### Preparation

Check the running kernel version with `uname -r` before upgrading.
dae uses eBPF and requires kernel version 5.17 or later.

Upgrade methods vary by distribution. This guide covers Armbian, Debian-based,
Red Hat and Fedora-based, and Arch-based distributions.

### Upgrade to a BTF Kernel on Armbian Linux

Precompiled kernels with BTF enabled are available for Armbian.

See [daeuniverse/armbian-btf-kernel](https://github.com/daeuniverse/armbian-btf-kernel).

### Upgrade the Kernel on Debian-based Linux

Debian-based distributions, including Armbian, can install a specific kernel
version. Search for the version you want, then install it:

```shell
# Sync databases.
sudo apt update
# Search available kernel versions.
apt-cache search ^linux-image
# Install specific image.
sudo apt install <specific-linux-image>
```

Reboot to use the installed kernel, then check its version:

```shell
sudo reboot
uname -r
```

For Debian only, use the following commands for an aggressive upgrade to the latest kernel.

> **Warning**: Debian's latest officially supported kernel is in `unstable` (codename SID). This is a rolling development distribution with the latest packages, not a fixed release. Upgrading to this kernel may introduce breaking changes. Proceed at your own risk.

Reference: [https://www.itsfoss.net/installing-linux-5-14-kernel-on-debian-11/](https://www.itsfoss.net/installing-linux-5-14-kernel-on-debian-11)

> **Note**: If you are not using Debian 11, change `Pin: release a=bullseye` below. For example, use `Pin: release a=buster` for Debian 10.

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

Reboot to use the installed kernel, then check its version:

```shell
sudo reboot
uname -r
```

### Upgrade the Kernel on Red Hat and Fedora Linux

Fedora, Red Hat, and Red Hat-based distributions can install a kernel from
their repositories. Fedora and Red Hat users can install a specific version.
Install the kernel, then reboot:

```bash
sudo yum install kernel
```

Reboot to use the installed kernel, then check its version:

```bash
sudo reboot
uname -r
```

### Upgrade the Kernel on Arch-based Linux

Arch and Arch-based distributions offer several kernels and regular security
patches. You can upgrade through the update manager or with `pacman`.

Manjaro and other Arch-based distributions often provide kernel updates through
their update managers. Running the system updater checks for the latest kernels.
Alternatively, search for and install a kernel with `pacman`:

```bash
# Search available kernel images.
pacman -Ss ^linux$
# Install specific kernel image.
pacman -S <specific-linux-image>
```

After installation, reboot and check the kernel version to confirm the upgrade:

```bash
sudo reboot
uname -r
```
