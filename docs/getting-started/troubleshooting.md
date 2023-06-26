# Troubleshooting

## Unknown bpf_trace_printk

```console
invalid argument: unknown func bpf_trace_printk
```

Solution:

Compile dae with CFLAG `-D__REMOVE_BPF_PRINTK`. See [build-by-yourself](build-by-yourself.md).

## No network after `dae suspend`

Do not set dae as the DNS in DHCP setting. For example, you can set `223.5.5.5` as DNS in your DHCP setting.

Because dae will not hijack any DNS request if it was suspended.

## PVE related

- [PVE NIC Hardware passthrough](https://github.com/daeuniverse/dae/issues/43)

## Binding to WAN but no network

### Troubleshoot local DNS service

If you use `adguardhome`, `mosdns` in `dns` section, refer to [external-dns](external-dns.md).

### Troubleshoot firewall

If you bind to wan, make sure firewall is stopped or `12345` is allowed by firewall. Don't worry about the security of this port because this port has its own firewall rule.

Usual firewalls on Linux:

```bash
ufw
firewalld
```

### Troubleshoot PPPoE

dae does not support PPPoE yet. We are working on it. However, binding to LAN for other machines should work fine.

## Binding to LAN but bad DNS in other machines

### Troubleshoot config of dae

Make sure you have bind to the correct LAN interfaces.

For example, if your use the same interface eth1 for WAN and LAN, write it as `wan_interface: eth1` and also in `lan_interface: eth1`. If the LAN interfaces you want to proxy are eth1 and docker0, write them both as `lan_interface: eth1,docker0`.

### Troubleshoot DNS

To verify on another machine in LAN:

```bash
curl -i 1.1.1.1
curl -i google.com
```

If the first line has a response and the second line doesn't, check whether port `53` is occupied by others on dae's machine.

```bash
netstat -ulpen|grep 53
# or
# lsof -i:53 -n
```

If does, stop the service process or change its listening port from 53 to others. Do not forget to modify `/etc/resolv.conf` to make DNS accessible (for example, with content `nameserver 223.5.5.5`, but do not use `nameserver 127.0.0.1`).

## Failed to load eBPF objects

> FATA[0022] load eBPF objects: field TproxyWanEgress: program tproxy_wan_egress: load program: argument list too long: 1617: (bf) r2 = r6: 1618: (85) call bpf_map_loo (truncated, 992 line(s) omitted)

If you use `clang-13` to compile dae, you may encounter this problem.

There are ways to resolve it:

1. Method 1: Use `clang-15` or higher versions to compile dae.
2. Method 2: Add CFLAGS `-D__UNROLL_ROUTE_LOOP` while compiling. However, it will increse memory occupation (or swap space) at the eBPF loading stage (about 180MB). For example, compile dae to ARM64 using `make CGO_ENABLE=0 GOARCH=arm64 CFLAGS="-D__UNROLL_ROUTE_LOOP -D__REMOVE_BPF_PRINTK"`.
