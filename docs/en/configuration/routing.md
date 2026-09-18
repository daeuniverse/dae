# Routing

## Examples

### Built-in outbounds

```shell
### Built-in outbounds: block, direct, must_rules

# must_rules means no redirecting DNS traffic to dae and continue to matching.
# For single rule, the difference between "direct" and "must_direct" is that "direct" will hijack and process DNS request
# (for traffic split use), but "must_direct" will not. "must_direct" is useful when there are traffic loops of DNS requests.
# "must_direct" can also be written as "direct(must)".
# Similarly, "must_groupname" is also supported to NOT hijack and process DNS traffic, which equals to "groupname(must)".
```

### Fallback

```shell
### fallback outbound
# If no rule matches, traffic will go through the outbound defined by fallback.
fallback: my_group
```

### Domain rules

```shell
### Domain rule
domain(suffix: v2raya.org) -> my_group  # equals to domain(v2raya.org) -> my_group 
domain(full: dns.google) -> my_group
domain(keyword: facebook) -> my_group
domain(regex: '\.goo.*\.com$') -> my_group
domain(geosite:category-ads) -> block
domain(geosite:cn)->direct
```

### Destination IP

```shell
### Dest IP rule
dip(8.8.8.8) -> direct
dip(101.97.0.0/16) -> direct
dip(geoip:private) -> direct
```

### Source IP

```shell
### Source IP rule
sip(192.168.0.0/24) -> my_group
sip(192.168.50.0/24) -> direct
```

### Destination ports

```shell
### Dest port rule
dport(80) -> direct
dport(10080-30000) -> direct
```

### Source ports

```shell
### Source port rule
sport(38563) -> direct
sport(10080-30000) -> direct
```

### Transport protocols

```shell
### Level 4 protocol rule:
l4proto(tcp) -> my_group
l4proto(udp) -> direct
```

### IP versions

```shell
### IP version rule:
ipversion(4) -> block
ipversion(6) -> ipv6_group
```

### Source MAC

```shell
### Source MAC rule
mac('02:42:ac:11:00:02') -> direct
```

### Process names

```shell
### Process Name rule (only support localhost process when binding to WAN)
pname(curl) -> direct
```

### DSCP

```shell
### DSCP rule (match DSCP; is useful for BT bypass). See https://github.com/daeuniverse/dae/discussions/295
dscp(0x4) -> direct
```

### Multiple domains

```shell
### Multiple domains rule
domain(keyword: google, suffix: www.twitter.com, suffix: v2raya.org) -> my_group
```

### Multiple IP addresses

```shell
### Multiple IP rule
dip(geoip:cn, geoip:private) -> direct
dip(9.9.9.9, 223.5.5.5) -> direct
sip(192.168.0.6, 192.168.0.10, 192.168.0.15) -> direct
```

### AND conditions

```shell
### 'And' rule
dip(geoip:cn) && dport(80) -> direct
dip(8.8.8.8) && l4proto(tcp) && dport(1-1023, 8443) -> my_group
dip(1.1.1.1) && sip(10.0.0.1, 172.20.0.0/16) -> direct
```

### NOT conditions

```shell
### 'Not' rule
!domain(geosite:google-scholar,
        geosite:category-scholar-!cn,
        geosite:category-scholar-cn
    ) -> my_group
```

### Combined conditions

```shell
### Little more complex rule
domain(geosite:geolocation-!cn) &&
    !domain(geosite:google-scholar,
            geosite:category-scholar-!cn,
            geosite:category-scholar-cn
        ) -> my_group
```

### Custom DAT files

```shell
### Customized DAT file
domain(ext:"yourdatfile.dat:yourtag")->direct
dip(ext:"yourdatfile.dat:yourtag")->direct
```

### Firewall marks

```shell
### Set fwmark
# Mark is useful when you want to redirect traffic to specific interface (such as wireguard) or for other advanced uses.

# An example of redirecting Disney traffic to wg0 is given here.
# You need set ip rule and ip table like this:
# 1. Set all traffic with mark 0x800/0x800 to use route table 1145:
# >> ip rule add fwmark 0x800/0x800 table 1145
# >> ip -6 rule add fwmark 0x800/0x800 table 1145
# 2. Set default route of route table 1145:
# >> ip route add default dev wg0 scope global table 1145
# >> ip -6 route add default dev wg0 scope global table 1145
# Notice that interface wg0, mark 0x800, table 1145 can be set by preferences, but cannot conflict.
# Notice also that dae marks its own egress traffic with an internal mark (0x100) unless
# so_mark_from_dae sets another one: a rule written for *unmarked* traffic does not match
# dae's own egress, and a rule that matches 0x100 affects dae's own traffic as well.
# 3. Set routing rules in dae config file.
domain(geosite:disney) -> direct(mark: 0x800)
```

### Must rules

```shell
### Must rules
# For following rules, DNS requests will be forcibly redirected to dae except from mosdns.
# Different from must_direct/must_my_group, traffic from mosdns will continue to match other rules.
pname(mosdns) -> must_rules
ip(geoip:cn) -> direct
domain(geosite:cn) -> direct
fallback: my_group
```

## Device-scoped domain whitelist (auto sniff-punt)

```shell
mac('aa:bb:cc:dd:ee:ff') && domain(geosite:docker, suffix:quay.io, geosite:github) -> my_group
mac('aa:bb:cc:dd:ee:ff') -> direct
```

The kernel matches `domain` conditions by looking up the connection's
destination IP in `domain_routing_map`. The key carries no source IP or MAC.
The value is the OR of the domain bitmaps of every DNS answer relayed through
dae that resolved to that IP, for as long as those DNS cache entries live. A
device that uses encrypted DNS (DoH/DoT) therefore still matches the whitelist
whenever another dae client, or the dae host, has resolved the destination IP
through dae. When no relayed answer covers the destination IP, the connection
carries no domain information and would use the fallback.

dae detects this rule pattern: a single-host `mac`/`sip` selector with positive
`domain` conditions, followed by a selector-only `direct`/`block` fallback.
It automatically inserts a kernel-space-only sniff-punt line before the
fallback. Connections without domain information are sent to userspace,
sniffed (TLS SNI / HTTP host / QUIC), and routed again through the same rule set
with the sniffed domain.

The recovery is conditional, because dae sniffs only some punted connections.
dae never sniffs TCP to destination ports 20, 21, 22, 25, 53, 119, 123, 161,
3306, 5432, 6379, 9200, 27017 and 11211; this list is hardcoded. dae also skips
a TCP connection when its first bytes are not a TLS handshake or an HTTP
request. After 3 consecutive sniff failures for the same destination, process
name, MAC and DSCP, dae skips sniffing that combination for 10 minutes. dae
sniffs UDP only when the source or destination port is 443 or 8443 and the
packet is a QUIC Initial. dae re-routes a skipped connection, or one whose
sniff yields no domain, without a domain, so the whitelist line cannot match
and the connection uses the fallback.

The device's non-whitelisted traffic still uses the fallback and is relayed
through userspace. This requires sniffing to be enabled (`sniffing_timeout > 0`,
`dial_mode != ip`). Disable the behavior with `auto_sniff_punt: false`.

## Parameter names and negated rules

The functions that take bare values — `pname`, `port`/`dport`, `sport`, `dscp`,
`ip`/`dip`, `sip`, `ipversion`, `l4proto`, `mac`, `qtype`, and the
response-routing `upstream` — reject an unsupported parameter name. The grammar
accepts `key: value` inside every call, and these parsers used to ignore an
unknown key, so `port(bogus_param: 443)` silently built the same match set as
`port(443)` and `pname(bogus_param: 1)` matched a process named `1`. Such a rule
now fails with `unsupported parameter key "bogus_param"` and names the accepted
form. The value prefixes these functions do understand — `geoip:`, `geosite:`
and `ext:` in `dip(geoip:cn)` or `dip(ext:"file.dat:tag")` — are unaffected,
as are the plain forms `pname(NetworkManager)` and `port(443)`. A configuration
that carries a mistyped parameter name on one of these functions stops
starting until the name is removed, so review the routing section before
upgrading.

The optimizer no longer merges single-function negated rules that share an
outbound. Rules are tried in order, so two lines

```shell
!domain(geosite:a) -> my_group
!domain(geosite:b) -> my_group
```

send traffic to `my_group` when it misses `a` **or** misses `b`. The merged form
`!domain(geosite:a, geosite:b)` inverts the whole set and only matches traffic
that misses **both**, which is narrower. dae now keeps the two lines as
written, so a configuration that relied on the merged behaviour sees those
rules match more traffic than before.
