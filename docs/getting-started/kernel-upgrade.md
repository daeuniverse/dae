# Kernel Upgrade Guide

A `kernel` is the core of any operating system. Before you start calling Linux an operating system, you need to know the basic concept and Linux’s birth history. **_Linux is not an operating system; mainly, Linux is a kernel_**.

## Upgrade Guide

### Disclaimer

Upgrading the Linux kernel is not easy; you must do this only if you find security errors or hardware interaction issues. If your system crashes, you might have to recover the whole system. Mostly, Linux distributions come with the most upgraded kernel. Upgrading the Linux kernel doesn’t delete or remove the previous kernel; it is kept inside the system.

> **Notes**
> You should not upgrade your kernel manually unless you want some specific driver support. You can roll back to the older kernel from the recovery menu of your Linux system. However, you may need to upgrade the kernel for hardware issues or security issues.

### Preparation

Before you start upgrading your Linux kernel, you must know the Kernel’s `current version` running inside your host machine. You may do so by `uname -r`. In case of `eBPF`, the minimum required version is `>= 5.8`

Various Linux distributions have different methods to upgrade the Linux kernel. This guide convers ways to upgrade the kernel to a desired version for most `Debian-based Linux`, `RedHar, Fedora based Linux`, and `Arch-based Linux` distributions.

> **Notes**
> Since `Dae` is builts with `eBPF`, your host must meet the minimum Kernel version, `>= 5.8` for dae to properly running.

### Upgrade Kernel on Debian-based Linux

```bash
sudo apt search linux-image

```

### Upgrade kernel on RedHat and Fedora Linux

Fedora, RedHat, and RedHat-based Linux distribution users can upgrade their Linux kernel manually by downloading the kernel from the repository.

Fedora and RedHat Linux users can install a specific version of Kernel on their system. You can run the following command-line on your Linux terminal to install any specific version kernel on your Linux system. After the installation is done, reboot your system to get the desired kernel on your Linux system.

```bash
sudo yum update kernel
sudo yum install kernel-{version}
sudo reboot
uname -r
```

### Upgrade kernel on Arch-based Linux

Arch and Arch-based Linux distributions have a `dynamic` variety of Linux kernel. Arch Linux updates its security patch regularly; that’s why you will see notable kernel and patch updates are available on Arch Linux. Here, I will describe two methods to upgrade the kernel on Arch Linux.

Manjaro and other Arch Linux distributions often offer kernel updates and upgrades via the conventional update manager. When you run the system updater on the Linux system, it checks for the latest kernels. You can use the following `pacman` command to check for the latest kernel on Arch Linux distributions.

```bash
sudo pacman -Syu
```

If it finds a new kernel, it will notify you to download and install it. You can choose whether you want to get the latest kernel or not. Once you agree to install, reboot your system after the installation is finished. Then, you can check the kernel version to ensure whether the kernel is upgraded or not.

```bash
sudo reboot
uname -r
```
