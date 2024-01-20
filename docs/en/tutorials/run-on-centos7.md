# Run on CentOS 7

> [!WARNING]
> CentOS 7 and RHEL 6.5/7 do not support eBPF out of the box; in other words, you must build the kernel (>= 5.8) yourself and install it.

## Introduction

CentOS 7 is a veteran Linux distribution, although its life cycle is not long, but there should still be some people using it. This article documents the steps to run dae on CentOS 7 or RHEL 6.5.

## Upgrade process

### Updating the kernel

Update the kernel that supports `BTF`

```bash
curl -s https://repo.cooluc.com/mailbox.repo > /etc/yum.repos.d/mailbox.repo
yum makecache
yum update kernel
```

> [!NOTE]
> The kernel is based on Linux 6.1 LTS, rebuilt to support `BBRv2`, and enables `eBPF` support. It can also be compiled by yourself, and the source package is available at <https://repo.cooluc.com/kernel/7/SRPMS/>

### Mount BPF

```bash
curl -s https://repo.cooluc.com/kernel/files/sys-fs-bpf.mount > /etc/systemd/system/sys-fs-bpf.mount
systemctl enable sys-fs-bpf.mount
```

### Mount Control Group v2

```bash
curl -s https://repo.cooluc.com/kernel/mount-cgroup2.service > /etc/systemd/system/mount-cgroup2.service
systemctl enable mount-cgroup2.service
```

### Reboot the system to make the kernel effective

> [!NOTE]
> Check the kernel version. If the version is `6.1.xx-1.el7.x86_64`, it means that the operation is successful.

```bash
uname -r
```

If the kernel version does not change, it means that the kernel has been updated before, and you need to rebuild the grub2 bootloader to make the new kernel the highest priority.

To set the latest kernel as the default:

```bash
grub2-set-default 0
```

To rebuild the kernel bootloader configuration:

```bash
grub2-mkconfig -o /boot/grub2/grub.cfg
```

### Running dae

Now you can download dae and run it as usual

```bash
mkdir -p /opt/dae && cd /opt/dae
wget https://github.com/daeuniverse/dae/releases/download/v0.2.2/dae-linux-x86_64.zip
unzip dae-linux-x86_64.zip && rm -f dae-linux-x86_64.zip
cp example.dae config.dae
chmod 600 config.dae
DAE_LOCATION_ASSET=$(pwd) ./dae-linux-x86_64 run -c config.dae
```
