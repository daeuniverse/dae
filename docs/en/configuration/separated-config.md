# Separate Configuration Files

Sometimes you want to break your configuration file into several files. It may be useful in these cases:
1. You want to switch nodes via modify the config file using tools like `sed`.
2. You copy other's configuration file and you want to overwrite some parts of it.

## An example

Directory Structure:

```sh
# tree /etc/dae
/etc/dae
├── config.d
│  ├── dns.dae
│  ├── node.dae
│  └── route.dae
└── config.dae
```

Config files:

```
# config.dae

# load all dae files placed in ./config.d/
include {
    config.d/*.dae
}
global {
    tproxy_port: 12345

    log_level: warn

    tcp_check_url: 'http://cp.cloudflare.com'
    udp_check_dns: 'dns.google.com:53'
    check_interval: 600s
    check_tolerance: 50ms

    #lan_interface: eth0
    wan_interface: eth0
    allow_insecure: false

    dial_mode: domain
    disable_waiting_network: false
    auto_config_kernel_parameter: true
    sniffing_timeout: 100ms
}
```

```
# dns.dae
dns {
    upstream {
        alidns: 'udp://dns.alidns.com:53'
        googledns: 'tcp+udp://dns.google.com:53'
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

```
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

```
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

Then run `dae` via:

```sh
dae run -c /etc/dae/config.dae
```

