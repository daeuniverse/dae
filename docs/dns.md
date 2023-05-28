# DNS

dae will intercept all UDP traffic to port 53 and sniff DNS. Here gives some examples and templates for DNS configuration.

## Examples

```shell
dns {
    # For example, if ipversion_prefer is 4 and the domain name has both type A and type AAAA records, the dae will only respond to type A queries and response empty answer to type AAAA queries.
    ipversion_prefer: 4

    upstream {
        # Value can be scheme://host:port.
        # Scheme list: tcp, udp, tcp+udp. Ongoing: https, tls, quic.
        # If host is a domain and has both IPv4 and IPv6 record, dae will automatically choose
        # IPv4 or IPv6 to use according to group policy (such as min latency policy).
        # Please make sure DNS traffic will go through and be forwarded by dae, which is REQUIRED for domain routing.
        # If dial_mode is "ip", the upstream DNS answer SHOULD NOT be polluted, so domestic public DNS is not recommended.

        alidns: 'udp://dns.alidns.com:53'
        googledns: 'tcp+udp://dns.google.com:53'
    }
    # The routing format of 'request' and 'response' is similar with section 'routing'.
    # See https://github.com/daeuniverse/dae/blob/main/docs/routing.md
    routing {
        # According to the request of dns query, decide to use which DNS upstream.
        # Match rules from top to bottom.
        request {
            # Built-in outbounds in 'request': asis, reject.
            # You can also use user-defined upstreams.

            # Available functions: qname, qtype.

            # DNS request name (omit suffix dot '.').
            qname(geosite:category-ads-all) -> reject
            qname(geosite:google@cn) -> alidns # Also see: https://github.com/v2ray/domain-list-community#attributes
            qname(suffix: abc.com, keyword: google) -> googledns
            qname(full: ok.com, regex: '^yes') -> googledns
            # DNS request type
            qtype(a, aaaa) -> alidns
            qtype(cname) -> googledns

            # If no match, fallback to this upstream.
            fallback: asis
        }
        # According to the response of dns query, decide to accept or re-lookup using another DNS upstream.
        # Match rules from top to bottom.
        response {
            # Built-in outbounds in 'response': accept, reject.
            # You can use user-defined upstreams.

            # Available functions: qname, qtype, upstream, ip.
            # Accept the response if the request is sent to upstream 'googledns'. This is useful to avoid loop.
            upstream(googledns) -> accept
            # If DNS request name is not in CN and response answers include private IP, which is most likely polluted
            # in China mainland. Therefore, resend DNS request to 'googledns' to get correct result.
            !qname(geosite:cn) && ip(geoip:private) -> googledns
            fallback: accept
        }
    }

}
```

## Templates

```shell
# Use alidns for China mainland domains and googledns for others.
dns {
  upstream {
    googledns: 'tcp+udp://dns.google.com:53'
    alidns: 'udp://dns.alidns.com:53'
  }
  routing {
    # According to the request of dns query, decide to use which DNS upstream.
    # Match rules from top to bottom.
    request {
      # Lookup China mainland domains using alidns, otherwise googledns.
      qname(geosite:cn) -> alidns
      # fallback is also called default.
      fallback: googledns
    }
  }
}
```

```shell
# Use alidns for all DNS queries and fallback to googledns if pollution result detected.
dns {
  upstream {
    googledns: 'tcp+udp://dns.google.com:53'
    alidns: 'udp://dns.alidns.com:53'
  }
  routing {
    # According to the request of dns query, decide to use which DNS upstream.
    # Match rules from top to bottom.
    request {
      # fallback is also called default.
      fallback: alidns
    }
    # According to the response of dns query, decide to accept or re-lookup using another DNS upstream.
    # Match rules from top to bottom.
    response {
      # Trusted upstream. Always accept its result.
      upstream(googledns) -> accept
      # Possibly polluted, re-lookup using googledns.
      !qname(geosite:cn) && ip(geoip:private) -> googledns
      # fallback is also called default.
      fallback: accept
    }
  }
}
```
