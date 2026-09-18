# Run on Alpine Linux

This tutorial covers Alpine Linux 3.20 and later.

- Alpine Linux 3.18 and later have full eBPF support out of the box. Earlier versions require a custom kernel build.
- Starting with Alpine Linux 3.20, some features required by dae are disabled for cross-architecture compatibility. Only `linux-virt` runs dae by default; `linux-lts` and `linux-edge` require a custom kernel build.

## Enable Community Repo

Run `setup-apkrepos` to open this menu:

```
 (f)    Find and use fastest mirror
 (s)    Show mirrorlist
 (r)    Use random mirror
 (e)    Edit /etc/apk/repositories with text editor
 (c)    Community repo enable
 (skip) Skip setting up apk repositories
```

Enter `c` to enable the community repository.

## Enable CGroups

Enable the `cgroups` service:

```sh
rc-update add cgroups boot
```

## Mount BPF

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

Check the syntax in `/etc/init.d/sysfs`. Errors will cause the `sysfs` service to fail.

## Install dae

Use [dae-installer](https://github.com/daeuniverse/dae-installer), which provides
an OpenRC service script. After installation, create
`/usr/local/etc/dae/config.dae` and set its permissions to 600 or 640:

```sh
chmod 640 /usr/local/etc/dae/config.dae
```

Once the configuration is ready, start dae:

```sh
rc-service dae start
```

## Start dae at Boot

Use `rc-update` to enable the dae service:

```sh
rc-update add dae
```
