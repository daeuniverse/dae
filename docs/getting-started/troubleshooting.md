# Troubleshooting

## Unknown bpf_trace_printk

```console
invalid argument: unknown func bpf_trace_printk
```

Solution:

Compile dae with CFLAG `-D__REMOVE_BPF_PRINTK`. See [build-by-yourself](build-by-yourself.md).

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
