# Run on Alpine Linux

**Note**: Alpine Linux 3.18 or newer verison has full eBPF support out-of-box, older version of Alpine Linux need to build kernel by yourself.

## Enable Community Repo

Edit apk's repositories config:

```sh
vi /etc/apk/repositories 
```

Then enable community repo, for example:

```ini
https://dl-cdn.alpinelinux.org/alpine/edge/main
https://dl-cdn.alpinelinux.org/alpine/edge/community
```

## Enable CGroup2

Edit OpenRC's config file:

```sh
vi /etc/rc.conf
```

Then edit `rc_cgroup_mode`, defaultly it would be `#rc_cgroup_mode="hybrid"`, we should switch to `unified` to make sure CGroup2 in default.

```ini
rc_cgroup_mode="unified"
```

Then enable `cgroups` service:

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

Be careful that the format of the script `/etc/init.d/sysfs` must be fine, or `sysfs` service will be failed.

## Install dae

Installer: <https://github.com/daeuniverse/dae-installer/>

This installer offered an OpenRC service script of dae, after installation, you should add a config file to `/usr/local/etc/dae/config.dae`, then set its permission to 600 or 640:

```sh
chmod 640 /usr/local/etc/dae/config.dae
```

If your config file is OK, then you can start dae service:

```sh
rc-service dae start
```

## Start at boot

Use `rc-update` to enable dae service:

```sh
rc-update add dae
```
