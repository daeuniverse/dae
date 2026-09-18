# Run on CentOS 7

> [!WARNING]
> CentOS 7 and RHEL 6.5/7 do not support eBPF out of the box. You must build and install kernel version 5.17 or later.

## Introduction

Run dae on CentOS 7 or RHEL 6.5 with the following steps.

## Upgrade process

### Update the kernel

Install a kernel with BTF support:

```bash
curl -s https://repo.cooluc.com/mailbox.repo > /etc/yum.repos.d/mailbox.repo
yum makecache
yum --enablerepo=mailbox-kernel update kernel
```

> [!NOTE]
> `mailbox.repo` ships the kernel in the `mailbox-kernel` section, which is disabled by default; `--enablerepo` turns it on for this command. The kernel is an LTS release rebuilt with BBRv2 and eBPF support. To compile it yourself, get the source package from <https://repo.cooluc.com/kernel/7/SRPMS>.

### Mount BPF

```bash
curl -fsS https://repo.cooluc.com/kernel/files/sys-fs-bpf.mount > /etc/systemd/system/sys-fs-bpf.mount
systemctl enable sys-fs-bpf.mount
```

### Mount control group v2

> [!NOTE]
> The address below no longer serves `mount-cgroup2.service` (HTTP 404 when this page was last checked). `curl -f` makes the failure visible instead of writing the error page into the unit file; supply your own unit that mounts cgroup v2 if the download fails.

```bash
curl -fsS https://repo.cooluc.com/kernel/mount-cgroup2.service > /etc/systemd/system/mount-cgroup2.service
systemctl enable mount-cgroup2.service
```

### Reboot to use the new kernel

> [!NOTE]
> Check the kernel version. A version newer than 5.17 that ends in `-1.el7.x86_64` confirms the upgrade:

```bash
uname -r
```

If the version has not changed, the kernel was updated previously. Rebuild the
grub2 bootloader configuration to give the new kernel the highest priority.

Set the latest kernel as the default:

```bash
grub2-set-default 0
```

Rebuild the bootloader configuration:

```bash
grub2-mkconfig -o /boot/grub2/grub.cfg
```

### Run dae

Download and run dae:

```bash
mkdir -p /opt/dae && cd /opt/dae
wget https://github.com/daeuniverse/dae/releases/download/v0.2.2/dae-linux-x86_64.zip
unzip dae-linux-x86_64.zip && rm -f dae-linux-x86_64.zip
cp example.dae config.dae
chmod 600 config.dae
DAE_LOCATION_ASSET=$(pwd) ./dae-linux-x86_64 run -c config.dae
```
