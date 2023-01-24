# dae

<img src="https://github.com/v2rayA/dae/blob/main/logo.png" border="0" width="20%">

***dae***, means goose, is a lightweight and high-performance transparent proxy solution.

In order to improve the traffic diversion performance as much as possible, dae runs the transparent proxy and traffic diversion suite in the linux kernel by eBPF. Therefore, we have the opportunity to make the direct traffic bypass the forwarding by proxy application and achieve true direct traffic through. Under such a magic trick, there is almost no performance loss and additional resource consumption for direct traffic.

As a successor of [v2rayA](https://github.com/v2rayA/v2rayA), dae abandoned v2ray-core to meet the needs of users more freely. In the initial conception, dae will serve soft router users first, and may also serve desktop users later.

## TODO

1. Control plane does not support MAC and other matching yet.
1. Dns upstream. Check dns upstream and source loop (whether upstream is also a client of us) and remind user to add source rule.
1. Routing performance optimization.
1. ...
