# Reload and Suspend

dae supports configuration reloading and program suspending, which can help you save a lot of time when modifying the configuration or temporarily suspend dae.

**Reload**

Generally, dae won't interrupt connections when reloading configuration. And reloading is much faster than restarting.

Usage:

```shell
dae reload
```

**Suspend**

It will be useful if you want to suspend dae temporarily and recover it later.

Usage:

```shell
dae suspend
```

If you want to recover, use reload:

```shell
dae reload
```
