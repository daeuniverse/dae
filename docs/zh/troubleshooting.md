# 故障排查

## `dae suspend` 后无网络

dae 暂停后不会劫持任何 DNS 请求。因此，请勿在 DHCP 设置中将 dae 设为 DNS 服务器，可改用 `223.5.5.5` 等地址。

## PVE 相关

- [PVE 网卡硬件直通](https://github.com/daeuniverse/dae/issues/43)

## 启动失败：残留的 `/run/netns/daens`

上一次运行可能残留命名 netns 的挂载点 `/run/netns/daens`。当 dae 运行在用户命名空间环境中（LXC 容器，例如 Proxmox VE 容器，或被沙箱化的服务）时，内核可能锁定该挂载点（`MNT_LOCKED`）：`umount`、`umount -l`、`umount -f` 一律返回 `EINVAL`，而 `rm` 返回 `EBUSY`，任何重试或标志组合都无法清除。此时 netns 本身已经消失，只剩这个挂载点。

当前版本会精确识别该特征并自动恢复：dae 用一个全新的 tmpfs 覆盖 `/run/netns`，打印告警说明本次恢复以及该覆盖隐藏的其他命名 netns，然后在干净的目录上启动。该覆盖会一直保留到下次重启——这是有意为之；移除它会让残留条目重新暴露。旧版本只会报出误导性的 `failed to create netns: open /run/netns/daens: file exists`。

dae 只对这一精确特征自动恢复。其他拒绝原因——错误码不同，或 dae 自身无权挂载（例如所在容器缺少相应的 `capability`）——会立即失败，并报出 `failed to clean up the stale named netns daens: ...`，其中带有真实的错误码。若失败源于权限，下面的人工兜底同样需要该权限：

```bash
sudo mount -t tmpfs -o mode=755 tmpfs /run/netns
sudo systemctl start dae
```

该命令必须在与 dae 相同的挂载命名空间中执行：若 dae 运行在容器内，请在容器内执行，而不是在宿主机上执行。

该 tmpfs 会隐藏同一挂载命名空间里的所有命名 netns：`ip netns list` 读取的正是这个目录，因此除 `daens` 之外的名字都会从中消失，`ip netns exec`、`ip netns pids`、`ip netns delete` 都找不到它们。被隐藏的命名空间及其进程仍在运行，只是名字不再可达。该覆盖是 dae 挂载命名空间中的一个挂载，因此会一直存在到重启为止，即使 dae 本身已经退出、或之后因其他原因启动失败也是如此。`/run` 中的内容不会在重启后保留：重启会同时清除覆盖和残留条目，其他命名 netns 会在其所属工具重新创建时恢复。参见 [issue #1109](https://github.com/daeuniverse/dae/issues/1109)。

## 绑定 WAN 后无网络

### 排查本地 DNS 服务

如果在 `dns` 部分使用 `adguardhome`、`mosdns`，请参阅 [外部 DNS](configuration/external-dns.md)。

### 排查防火墙

dae 会把劫持到的数据包从 WAN egress 和 LAN ingress 的 tc hook 经 `dae0` 设备转入其私有的 `daens` 网络命名空间。在 `daens` 内，`tproxy_dae0peer_ingress` 设置 fwmark `0x8000000`。命名空间内的策略路由（路由表 `2023`）再把数据包送到 `tproxy_port`（默认 `12345`）上的 tproxy 监听器。主机的 `INPUT` 链看不到这些数据包，也看不到该 fwmark，因此主机防火墙针对该 fwmark 或该端口的规则对它们不起作用。dae 不会为该端口添加防火墙规则，并忽略已弃用的 `auto_config_firewall_rule` 选项。

主机防火墙能看到的是 dae 自身的出站连接，以及 dae 重新注入 WAN 接口的应答数据包；放行 established 和 related 流量的规则集会让这两类都通过。如果绑定 WAN 后无网络，请先停止防火墙以确认原因，再确认它仍放行 established 和 related 流量；ufw 与 firewalld 的默认规则集都放行这类流量。

Linux 上常见的防火墙：

```bash
ufw
firewalld
```

#### ufw

`/etc/ufw/before*.rules` 的默认规则会放行 established 和 related 流量，已覆盖 dae 重新注入 WAN 接口的应答数据包。旧的教程会在 `/etc/ufw/before*.rules` 中添加以下 fwmark 规则。因为被劫持的数据包只在 `daens` 内带有 fwmark `0x8000000`，所以这些规则在主机上匹配不到任何数据包，dae 不需要它们：

```bash
# before.rules
-A ufw-before-input -m mark --mark 0x8000000 -j ACCEPT

# before6.rules
-A ufw6-before-input -m mark --mark 0x8000000 -j ACCEPT
```

#### firewalld

firewalld 的默认 zone 会放行 established 和 related 流量，已覆盖 dae 重新注入 WAN 接口的应答数据包。旧的教程会在每次开机和防火墙规则变更后执行以下命令。因为被劫持的数据包只在 `daens` 内带有 fwmark `0x8000000`，所以该命令在主机上匹配不到任何数据包，dae 不需要它：

```bash
sudo nft 'insert rule inet firewalld filter_INPUT mark 0x8000000 accept'
```

### 排查 PPPoE

旧版本 dae 不支持 PPPoE，请使用最新版本。

## 绑定 LAN 但其他计算机 DNS 异常

### 排查 dae 配置

请确保绑定到正确的 LAN 接口。

| 接口用途 | 配置 |
| --- | --- |
| WAN 和 LAN 共用 `eth1` | 同时设置 `wan_interface: eth1` 和 `lan_interface: eth1` |
| 需要代理的 LAN 接口为 `eth1` 和 `docker0` | 设置 `lan_interface: eth1,docker0` |

### 排查 DNS

在 LAN 中另一台计算机上验证：

```bash
curl -i 1.1.1.1
curl -i google.com
```

若第一行有响应而第二行没有，请检查 dae 所在计算机的端口 `53` 是否被其他程序占用。

```bash
netstat -ulpen|grep 53
# or
# lsof -i:53 -n
```

若端口被占用，请停止该服务进程，或将其监听端口从 53 改为其他端口。同时修改 `/etc/resolv.conf`，确保 DNS 可访问。例如，写入 `nameserver 223.5.5.5`，不要使用 `nameserver 127.0.0.1`。

## 无法加载 eBPF 对象

> FATA[0022] load eBPF objects: field TproxyWanEgress: program tproxy_wan_egress: load program: argument list too long: 1617: (bf) r2 = r6: 1618: (85) call bpf_map_loo (truncated, 992 line(s) omitted)

此错误在用 `clang-13` 编译 dae 时出现。请改用 `clang-15` 或更高版本编译，或直接从 [releases](https://github.com/daeuniverse/dae/releases) 下载二进制文件。`-D__UNROLL_ROUTE_LOOP` 没有任何效果：该宏在 `control/kern/tproxy.c` 中只是一行被注释掉的定义，没有对应代码。路由始终使用 `bpf_loop`，且 dae 在低于 `5.17.0` 的内核上拒绝启动。
