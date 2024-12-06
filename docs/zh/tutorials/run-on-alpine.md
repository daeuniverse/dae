# 在 Alpine Linux 上运行

**注意：** 
1. Alpine Linux 3.18 或更新版本已完全支持开箱即用的 eBPF，旧版本的 Alpine Linux 需要自己构建内核。
2. 从 3.20 版开始，由于 Alpine Linux 的跨 CPU 架构兼容性问题，官方禁用了 dae 所需的一些功能，因此默认情况下只能使用 `linux-virt` 运行 dae。对于 `linux-lts` 或 `linux-edge`，你应该自己构建内核。
3. 本教程适用于 Alpine Linux 3.20 及更新版本。

## 启用 Community Repo

运行 `setup-apkrepos` 命令，然后你会看到这样的菜单列表：

```
 (f)    Find and use fastest mirror
 (s)    Show mirrorlist
 (r)    Use random mirror
 (e)    Edit /etc/apk/repositories with text editor
 (c)    Community repo enable
 (skip) Skip setting up apk repositories
```

然后输入 ``c` 启用社区仓库。

## 启用 CGgroups

启用 `cgroups` 服务：

```sh
rc-update add cgroups boot
```

## 挂载 bpf

编辑 `/etc/init.d/sysfs`：

```sh
vi /etc/init.d/sysfs
```

在 `mount_misc` 部分添加以下内容：

```sh
        # Setup Kernel Support for bpf file system
        if [ -d /sys/fs/bpf ] && ! mountinfo -q /sys/fs/bpf; then
                if grep -qs bpf /proc/filesystems; then
                ebegin "Mounting eBPF filesystem"
                mount -n -t bpf -o ${sysfs_opts} bpffs /sys/fs/bpf
                eend $?
                fi
        fi
```

请注意，脚本 `/etc/init.d/sysfs` 的格式必须正确，否则 `/etc/init.d/sysfs` 将被删除。

## 安装 dae

安装程序： <https://github.com/daeuniverse/dae-installer/>

此安装程序提供了一个 dae 的 OpenRC 服务脚本，安装后，您需要在 `/usr/local/etc/dae/config.dae` 中添加一个配置文件，然后将其权限设置为 600 或 640：

```sh
chmod 640 /usr/local/etc/dae/config.dae
```

如果配置文件已准备就绪，那就可以启动 dae 服务了：

```sh
rc-service dae start
```

## 随系统启动

使用 `rc-update` 启用 dae 服务：

```sh
rc-update add dae
```