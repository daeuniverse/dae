# CentOS 7

> [!WARNING]
> CentOS 7 和 RHEL 6.5/7 默认不支持 eBPF，必须自行构建并安装内核（>= 5.17）。

## 简介

CentOS 7 是较早的 Linux 发行版，生命周期已近尾声，但仍有用户使用。本页记录在 CentOS 7 或 RHEL 6.5 上运行 dae 的步骤。

## 升级流程

### 更新内核

更新到支持 `BTF` 的内核。

```bash
curl -s https://repo.cooluc.com/mailbox.repo > /etc/yum.repos.d/mailbox.repo
yum makecache
yum --enablerepo=mailbox-kernel update kernel
```

> [!NOTE]
> `mailbox.repo` 把内核放在 `mailbox-kernel` 段，默认关闭，所以这条命令要带 `--enablerepo`。该内核是重新构建的 LTS 版本，支持 BBRv2 与 eBPF。也可以自行编译，源码包位于 <https://repo.cooluc.com/kernel/7/SRPMS/>。

### 挂载 BPF

```bash
curl -fsS https://repo.cooluc.com/kernel/files/sys-fs-bpf.mount > /etc/systemd/system/sys-fs-bpf.mount
systemctl enable sys-fs-bpf.mount
```

### 挂载 Control Group v2

> [!NOTE]
> 下面这个地址已不再提供 `mount-cgroup2.service`（最近一次检查返回 HTTP 404）。`curl -f` 会让失败显示出来，而不是把错误页写进单元文件；下载失败时请自行提供挂载 cgroup v2 的单元。

```bash
curl -fsS https://repo.cooluc.com/kernel/mount-cgroup2.service > /etc/systemd/system/mount-cgroup2.service
systemctl enable mount-cgroup2.service
```

### 重启系统使内核生效

> [!NOTE]
> 检查内核版本。若版本高于 5.17 且以 `-1.el7.x86_64` 结尾，表示操作成功。

```bash
uname -r
```

若内核版本未变，表示此前已更新过内核，需要重新构建 grub2 引导程序，使新内核具有最高优先级。

要将最新内核设为默认：

```bash
grub2-set-default 0
```

要重新构建内核引导程序配置：

```bash
grub2-mkconfig -o /boot/grub2/grub.cfg
```

### 运行 dae

现在可以照常下载并运行 dae。

```bash
mkdir -p /opt/dae && cd /opt/dae
wget https://github.com/daeuniverse/dae/releases/download/v0.2.2/dae-linux-x86_64.zip
unzip dae-linux-x86_64.zip && rm -f dae-linux-x86_64.zip
cp example.dae config.dae
chmod 600 config.dae
DAE_LOCATION_ASSET=$(pwd) ./dae-linux-x86_64 run -c config.dae
```
