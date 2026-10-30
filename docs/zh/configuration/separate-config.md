# 拆分配置文件

以下情况适合将配置拆分为多个文件：

- 通过 `sed` 等工具修改配置文件来切换节点。
- 复制他人的配置文件后，覆盖其中的某些部分。

## 示例

目录结构：

```sh
# tree /etc/dae
/etc/dae
├── config.d
│  ├── dns.dae
│  ├── node.dae
│  └── route.dae
└── config.dae
```

入口配置文件是传递给 `dae -c ...` 的文件。`include` 路径按以下规则处理：

| 路径类型 | 示例 | 处理方式 |
| --- | --- | --- |
| 相对路径 | `config.d/*.dae` | 相对于入口配置文件所在目录解析，而非当前工作目录 |
| 绝对路径 | `/etc/dae/config.d/*.dae` | 按原样使用 |

出于安全原因，dae 仅允许包含入口配置目录下的文件。

配置文件如下：

```jsonc
# config.dae

# load all dae files placed in ./config.d/
include {
    # Relative path example:
    config.d/*.dae

    # Absolute path example:
    /etc/dae/config.d/*.dae
}
global {
    tproxy_port: 12345

    log_level: warn

    tcp_check_url: 'http://cp.cloudflare.com'
    udp_check_dns: 'dns.google:53'
    check_interval: 600s
    check_tolerance: 50ms

    #lan_interface: eth0
    wan_interface: eth0
    allow_insecure: false

    dial_mode: domain
    disable_waiting_network: false
    auto_config_kernel_parameter: true
    sniffing_timeout: 30ms
}
```

```jsonc
# dns.dae
dns {
    upstream {
        alidns: 'udp://dns.alidns.com:53'
        googledns: 'tcp+udp://dns.google:53'
    }

    routing {
        request {
            qname(geosite:category-ads) -> reject
            qname(geosite:category-ads-all) -> reject
            fallback: alidns
        }
        response {
            upstream(googledns) -> accept
            !qname(geosite:cn) && ip(geoip:private) -> googledns
            fallback: accept
        }
    }
}
```

```jsonc
# node.dae
node {
    node1: 'xxx'
    node2: 'xxx'
}

subscription {
    my_sub: 'https://www.example.com/subscription/link'
}

group {
    my_group {
        filter: subtag(my_sub) && !name(keyword: 'ExpireAt:')
        policy: min_moving_avg
    }

    local_group {
        filter: name(node1, node2)
        policy: fixed(0)
    }

    manual_group {
        filter: subtag(my_sub)
        policy: select
    }
}
```

`select` 保留一个可在运行时切换的成员，TCP 与 UDP 分别保存选择。`select(n)`
表示初始选择第 n 个成员。运行时选择只存在内存中：不会写回配置文件，reload
或重启后回到配置的索引。可通过原生 API 的
`PUT /api/v1/groups/{group_id}/selection` 切换（见[原生 API](./api.md)）。

```jsonc
# route.dae
routing {
    pname(NetworkManager) -> direct
    dip(224.0.0.0/3, 'ff00::/8') -> direct
    dip(geoip:private) -> direct

    dip(1.14.5.14) -> direct

    domain(geosite:openai) -> local_group
    dip(geoip:cn) -> direct
    domain(geosite:cn) -> direct
    domain(geosite:category-scholar-cn) -> direct
    domain(geosite:geolocation-cn) -> direct


    fallback: my_group
}
```

然后通过以下命令运行 `dae`：

```sh
dae run -c /etc/dae/config.dae
```
