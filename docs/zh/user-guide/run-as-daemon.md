# 作为守护进程运行

在使用 [systemd](https://wiki.debian.org/systemd) 管理服务的发行版上，dae 可以作为守护进程运行，并设置为开机自动启动。

## 前提条件

### 可选的 Geo 数据文件

为便于流量分流，dae 使用 [geoip.dat](https://github.com/v2fly/geoip/releases/latest) 和 [geosite.dat](https://github.com/v2fly/domain-list-community/releases/latest) 数据。

```shell
mkdir -p /usr/local/share/dae/
pushd /usr/local/share/dae/
curl -L -o geoip.dat https://github.com/v2fly/geoip/releases/latest/download/geoip.dat
curl -L -o geosite.dat https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat
popd
```

### 配置文件

> **注意**：建议将配置文件保存在 `/etc/dae` 下。

下载示例配置文件：

```bash
mkdir -p /etc/dae
curl -L -o /etc/dae/config.dae https://github.com/daeuniverse/dae/raw/main/example.dae
chmod 600 /etc/dae/config.dae
```

## 下载预编译二进制文件

发布版本位于 <https://github.com/daeuniverse/dae/releases>。

> **注意**：如需体验新功能，可使用夜间（最新）构建。新变更通常通过 PR 提出，GitHub Actions 构建工作流会提供跨平台可执行二进制文件。新功能有时存在缺陷，使用者需自行承担风险。测试最新构建有助于分析功能稳定性并修复潜在问题。

夜间构建位于 <https://github.com/daeuniverse/dae/actions/workflows/build-nightly.yml>。

```bash
sudo chmod +x ./dae
sudo install -Dm755 dae /usr/bin/

# helper
dae [-h,--help]
# check version
dae version
```

## 安装服务

```bash
# download the sample systemd.service
sudo curl -L -o /etc/systemd/system/dae.service https://github.com/daeuniverse/dae/raw/main/install/dae.service

# reload and restart daemon to take effect
sudo systemctl daemon-reload
sudo systemctl enable dae --now
sudo systemctl status dae
```

## 内存与 THP

`GOMEMLIMIT` 根据进程的 cgroup 上限计算，而不是根据服务单元的设置计算。计算时仅使用 `memory.max`，软限制为该上限的 90%。显式设置的 `GOMEMLIMIT` 环境变量始终优先。

随附的服务单元已不再设置 `MemoryHigh`，因为运行时无法将其识别为内存上限。

如果主机将 THP（transparent huge pages）设为 `always`，即使 Go 堆中的存活对象占用没有增加，内核也可能使 dae 的驻留内存增大。

dae 在每次启动、重载和回滚时，都会以当前的 `disable_thp` 值为自身进程调用 `prctl(PR_SET_THP_DISABLE)`。`true` 传入 1，为该进程禁用 THP。默认值 `false` 传入 0，清除该进程已有的 THP 禁用状态（包括从父进程继承的），因此 dae 遵循系统级的 THP 设置。两个值都不会修改 `/sys/kernel/mm/transparent_hugepage`：

```shell
global {
  disable_thp: true
}
```

## 检查系统日志

```bash
sudo journalctl -xefu dae
```
