# dae

<img src="https://github.com/v2rayA/dae/blob/main/logo.png" border="0" width="20%">

***dae***, means goose, is a lightweight and high-performance transparent proxy solution.

In order to improve the traffic diversion performance as much as possible, dae runs the transparent proxy and traffic diversion suite in the linux kernel by eBPF. Therefore, we have the opportunity to make the direct traffic bypass the forwarding by proxy application and achieve true direct traffic through. Under such a magic trick, there is almost no performance loss and additional resource consumption for direct traffic.

As a successor of [v2rayA](https://github.com/v2rayA/v2rayA), dae abandoned v2ray-core to meet the needs of users more freely. In the initial conception, dae will serve soft router users first, and may also serve desktop users later.

## Usage

Build:
```shell
git clone https://github.com/v2rayA/dae.git
cd dae
make
```

Run:
```shell
./dae run -c example.dae
```

See [example.dae](https://github.com/v2rayA/dae/blob/main/example.dae).

## TODO

1. Check dns upstream and source loop (whether upstream is also a client of us) and remind the user to add sip rule.
1. Domain routing performance optimization.
1. DisableL4Checksum by link.
1. Handle the case that nodes do not support UDP.
1. L4Checksum problem.
1. Config support list like: `wan_interface: [wlp5s0, eth0]`.
1. ...
