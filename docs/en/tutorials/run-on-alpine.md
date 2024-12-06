# Run on Alpine Linux

**Note:** 
1. Alpine Linux 3.18 or newer verison has full eBPF support out-of-box, older version of Alpine Linux need to build kernel by yourself.
2. From version 3.20, Alpine Linux has officially disabled some features dae needed beacuse of Alpine Linux's cross CPU architectures compatibility, so only `linux-virt` can be used to run dae defaultly. For `linux-lts` or `linux-edge`, you should build the kernel by yourself.
3. This tutorial is for Alpine Linux 3.20 and newer.

## Enable Community Repo

Run `setup-apkrepos` command, then you'll get a menu list like this:

```
 (f)    Find and use fastest mirror
 (s)    Show mirrorlist
 (r)    Use random mirror
 (e)    Edit /etc/apk/repositories with text editor
 (c)    Community repo enable
 (skip) Skip setting up apk repositories
```

Then input `c` to enable community repo.

## Enable CGroups

Enable `cgroups` service:

```sh
rc-update add cgroups boot
```

## Mount bpf

Edit `/etc/init.d/sysfs`:

```sh
vi /etc/init.d/sysfs
```

Add the following to the `mount_misc` section:

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

Be careful that the format of the script `/etc/init.d/sysfs` must be correct, or `sysfs` service will be failed.

## Install dae

Installer: <https://github.com/daeuniverse/dae-installer/>

This installer offered an OpenRC service script of dae, after installation, you should add a config file to `/usr/local/etc/dae/config.dae`, then set its permission to 600 or 640:

```sh
chmod 640 /usr/local/etc/dae/config.dae
```

If your config file is ready to work, then you can start dae service:

```sh
rc-service dae start
```

## Start dae at boot

Use `rc-update` to enable dae service:

```sh
rc-update add dae
```
