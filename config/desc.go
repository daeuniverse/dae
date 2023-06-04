/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2023, daeuniverse Organization <dae@v2raya.org>
 */

package config

type Desc map[string]string

var SectionSummaryDesc = Desc{
	"subscription": "Subscriptions defined here will be resolved as nodes and merged as a part of the global node pool.\nSupport to give the subscription a tag, and filter nodes from a given subscription in the group section.",
	"node":         "Nodes defined here will be merged as a part of the global node pool.",
	"dns":          "See more at https://github.com/daeuniverse/dae/blob/main/docs/dns.md.",
	"group":        "Node group. Groups defined here can be used as outbounds in section \"routing\".",
	"routing": `Traffic follows this routing. See https://github.com/daeuniverse/dae/blob/main/docs/routing.md for full examples.
Notice: domain traffic split will fail if DNS traffic is not taken over by dae.
Built-in outbound: direct, must_direct, block.
Available functions: domain, sip, dip, sport, dport, ipversion, l4proto, pname, mac.
Available keys in domain function: suffix, keyword, regex, full. No key indicates suffix.
domain: Match domain.
sip: Match source IP. CIDR format is also supported.
dip: Match dest IP. CIDR format is also supported.
sport: Match source port. Range like 8000-9000 is also supported.
dport: Match dest port. Range like 8000-9000 is also supported.
ipversion: Match IP version. Available values: 4, 6.
l4proto: Match level 4 protocol. Available values: tcp, udp.
pname: Match process name. It only works on WAN mode and for localhost programs.
mac: Match source MAC address. It works on LAN mode.`,
}

var SectionDescription = map[string]Desc{
	"GlobalDesc": GlobalDesc,
	"DnsDesc":    DnsDesc,
	"GroupDesc":  GroupDesc,
}

var GlobalDesc = Desc{
	"tproxy_port":           "tproxy port to listen on. It is NOT a HTTP/SOCKS port, and is just used by eBPF program.\nIn normal case, you do not need to use it.",
	"tproxy_port_protect":   "Set it true to protect tproxy port from unsolicited traffic. Set it false to allow users to use self-managed iptables tproxy rules.",
	"so_mark_from_dae":      "If not zero, traffic sent from dae will be set SO_MARK. It is useful to avoid traffic loop with iptables tproxy rules.",
	"log_level":             "Log level: error, warn, info, debug, trace.",
	"tcp_check_url":         "Node connectivity check.\nHost of URL should have both IPv4 and IPv6 if you have double stack in local.\nConsidering traffic consumption, it is recommended to choose a site with anycast IP and less response.",
	"tcp_check_http_method": "The HTTP request method to `tcp_check_url`. Use 'CONNECT' by default because some server implementations bypass accounting for this kind of traffic.",
	"udp_check_dns":         "This DNS will be used to check UDP connectivity of nodes. And if dns_upstream below contains tcp, it also be used to check TCP DNS connectivity of nodes.\nThis DNS should have both IPv4 and IPv6 if you have double stack in local.",
	"check_interval":        "Interval of connectivity check for TCP and UDP",
	"check_tolerance":       "Group will switch node only when new_latency <= old_latency - tolerance.",
	"lan_interface":         "The LAN interface to bind. Use it if you want to proxy LAN.",
	"wan_interface":         "The WAN interface to bind. Use it if you want to proxy localhost. Use \"auto\" to auto detect.",
	"allow_insecure":        "Allow insecure TLS certificates. It is not recommended to turn it on unless you have to.",
	"dial_mode": `Optional values of dial_mode are:
1. "ip". Dial proxy using the IP from DNS directly. This allows your ipv4, ipv6 to choose the optimal path respectively, and makes the IP version requested by the application meet expectations. For example, if you use curl -4 ip.sb, you will request IPv4 via proxy and get a IPv4 echo. And curl -6 ip.sb will request IPv6. This may solve some wierd full-cone problem if your are be your node support that.Sniffing will be disabled in this mode.
2. "domain". Dial proxy using the domain from sniffing. This will relieve DNS pollution problem to a great extent if have impure DNS environment. Generally, this mode brings faster proxy response time because proxy will re-resolve the domain in remote, thus get better IP result to connect. This policy does not impact routing. That is to say, domain rewrite will be after traffic split of routing and dae will not re-route it.
3. "domain+". Based on domain mode but do not check the reality of sniffed domain. It is useful for users whose DNS requests do not go through dae but want faster proxy response time. Notice that, if DNS requests do not go through dae, dae cannot split traffic by domain.
4. "domain++". Based on domain+ mode but force to re-route traffic using sniffed domain to partially recover domain based traffic split ability. It doesn't work for direct traffic and consumes more CPU resources.`,
	"disable_waiting_network":      "Disable waiting for network before pulling subscriptions.",
	"auto_config_kernel_parameter": "Automatically configure Linux kernel parameters like ip_forward and send_redirects. Check out https://github.com/daeuniverse/dae/blob/main/docs/getting-started/kernel-parameters.md to see what will dae do.",
	"sniffing_timeout":             "Timeout to waiting for first data sending for sniffing. It is always 0 if dial_mode is ip. Set it higher is useful in high latency LAN network.",
	"tls_implementation":           "TLS implementation. \"tls\" is to use Go's crypto/tls. \"utls\" is to use uTLS, which can imitate browser's Client Hello.",
	"utls_imitate":                 "The Client Hello ID for uTLS to imitate. This takes effect only if tls_implementation is utls. See more: https://github.com/daeuniverse/dae/blob/331fa23c16/component/outbound/transport/tls/utls.go#L17",
}

var DnsDesc = Desc{
	"ipversion_prefer": "For example, if ipversion_prefer is 4 and the domain name has both type A and type AAAA records, the dae will only respond to type A queries and response empty answer to type AAAA queries.",
	"fixed_domain_ttl": "Give a fixed ttl for domains. Zero means that dae will request to upstream every time and not cache DNS results for these domains.",
	"upstream":         "Value can be scheme://host:port, where the scheme can be tcp/udp/tcp+udp.\nIf host is a domain and has both IPv4 and IPv6 record, dae will automatically choose IPv4 or IPv6 to use according to group policy (such as min latency policy).\nPlease make sure DNS traffic will go through and be forwarded by dae, which is REQUIRED for domain routing.\nIf dial_mode is \"ip\", the upstream DNS answer SHOULD NOT be polluted, so domestic public DNS is not recommended.",
	"request": `DNS requests will follow this routing.
Built-in outbound: asis.
Available functions: qname, qtype`,
	"response": `DNS responses will follow this routing.
Built-in outbound: accept, reject.
Available functions: qname, qtype, ip, upstream`,
}

var GroupDesc = Desc{
	"filter": `Filter nodes from the global node pool defined by the "subscription" and "node" sections.
Available functions: name, subtag. Not operator is supported.
Available keys in name function: keyword, regex. No key indicates full match.
Available keys in subtag function: regex. No key indicates full match.`,
	"policy": `Dialer selection policy. For each new connection, select a node as dialer from group by this policy.
Available values: random, fixed, min, min_avg10, min_moving_avg.
random: Select randomly.
fixed: Select the fixed node. Connectivity check will be disabled.
min: Select node by the latency of last check.
min_avg10: Select node by the average of latencies of last 10 checks.
min_moving_avg: Select node by the moving average of latencies of checks, which means more recent latencies have higher weight.
`,
}
