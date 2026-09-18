# Reload and Suspend

dae can reload its configuration or suspend temporarily without restarting.

## Reload

Reloading is much faster than restarting and generally preserves existing
connections. It also updates all subscriptions at once:

```shell
dae reload
```

## Suspend

Suspend dae temporarily:

```shell
dae suspend
```

## Resume

To resume, reload:

```shell
dae reload
```
