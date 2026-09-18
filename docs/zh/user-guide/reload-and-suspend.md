# 重载与暂停

dae 可在不重启的情况下重载配置或临时暂停。

## 重载

dae 重载配置时通常不会中断现有连接，且比重启快得多。执行重载还会同时更新全部订阅。

```shell
dae reload
```

## 暂停

暂停 dae：

```shell
dae suspend
```

## 恢复

使用重载命令恢复：

```shell
dae reload
```
