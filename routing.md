# routing

## Examples:

```shell
# Built-in outbounds: block, direct

# If no rule matches, traffic will go through the outbound defined by final.
final: my_group

# Domain rule
domain(suffix: v2raya.org) -> my_group
# equals to domain(v2raya.org) -> my_group
domain(full: dns.google) -> my_group
domain(keyword: facebook) -> my_group
domain(regexp: '\.goo.*\.com$') -> my_group
domain(geosite:category-ads) -> block
domain(geosite:cn)->direct

# Dest IP rule
ip(8.8.8.8) -> direct
ip(101.97.0.0/16) -> direct
ip(geoip:private) -> direct

# Source IP rule
sip(192.168.0.0/24) -> my_group
sip(192.168.50.0/24) -> direct

# Dest port rule
port(80) -> direct
port(10080-30000) -> direct

# Source port rule
sport(38563) -> direct
sport(10080-30000) -> direct

# Source MAC rule
mac('02:42:ac:11:00:02') -> direct

# Level 4 protocol rule:
l4proto(tcp) -> my_group
l4proto(udp) -> direct

# IP version rule:
ipversion(4) -> block
ipversion(6) -> ipv6_group

# Multiple domains rule
domain(keyword: google, suffix: www.twitter.com, suffix: v2raya.org) -> my_group
# Multiple IP rule
ip(geoip:cn, geoip:private) -> direct
ip(9.9.9.9, 223.5.5.5) -> direct
sip(192.168.0.6, 192.168.0.10, 192.168.0.15) -> direct

# 'And' rule
ip(geoip:cn) && port(80) -> direct
ip(8.8.8.8) && l4proto(tcp) && port(1-1023, 8443) -> my_group
ip(1.1.1.1) && sip(10.0.0.1, 172.20.0.0/16) -> direct

# 'Not' rule
!domain(geosite:google-scholar,
        geosite:category-scholar-!cn,
        geosite:category-scholar-cn
    ) -> my_group

# Little more complex rule
domain(geosite:geolocation-!cn) &&
    !domain(geosite:google-scholar,
            geosite:category-scholar-!cn,
            geosite:category-scholar-cn
        ) -> my_group
```
