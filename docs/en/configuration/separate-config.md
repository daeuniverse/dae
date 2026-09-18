# Separate Configuration Files

Split your configuration into several files when you want to:

- Switch nodes by modifying a configuration file with tools such as `sed`.
- Override parts of someone else's configuration.

## Example

Directory structure:

```sh
# tree /etc/dae
/etc/dae
├── config.d
│  ├── dns.dae
│  ├── node.dae
│  └── route.dae
└── config.dae
```

`include` paths follow these rules:

- Relative paths, such as `config.d/*.dae`, resolve relative to the entry configuration file's directory, not the current working directory. The entry file is the file passed to `dae -c ...`.
- Absolute paths, such as `/etc/dae/config.d/*.dae`, are used as-is.
- For security, dae only allows included files under the entry configuration directory.

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
}
```

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

Run dae with the entry configuration file:

```sh
dae run -c /etc/dae/config.dae
```
