# DNS

dae intercepts all UDP and TCP traffic to port 53 that it routes or that leaves the host, and sniffs DNS. Only a rule that resolves to `must_direct` keeps port 53 traffic away from dae; `direct` alone still hands it to the DNS module. Two cases never reach the DNS module: a UDP query from a LAN client to a socket on the dae host itself, such as a local dnsmasq on port 53, is delivered to that socket before routing; and queries over the loopback interface never pass a dae hook. A TCP query from a LAN client to that local socket still goes through routing.

dae does not reassemble IP fragments: it processes only the first fragment of a datagram and passes later fragments through unchanged, so a fragmented UDP DNS message cannot be intercepted correctly. When the resolver that answers LAN clients sends its own upstream queries through a `must_direct` rule, dae never sees those answers and learns no domain for the returned IPs, so `domain()` rules do not match the clients' traffic.

## URI schemes

### DoH3

```
h3://<host>:<port>/<path>
http3://<host>:<port>/<path>

default port: 443
default path: /dns-query
```

### DoH

```
https://<host>:<port>/<path>

default port: 443
default path: /dns-query
```

### DoT

```
tls://<host>:<port>

default port: 853
```

### DoQ

```
quic://<host>:<port>

default port: 853
```

### UDP

```
udp://<host>:<port>

default port: 53
```

### TCP

```
tcp://<host>:<port>

default port: 53
```

### TCP and UDP

```
tcp+udp://<host>:<port>

default port: 53
```

For queries that dae forwards on behalf of clients, dae retries a truncated
answer (`TC=1`, RFC 1035 §4.2.1) over TCP, as RFC 7766 §5 requires. For a
`udp://` upstream, dae retries only after a truncated answer; for a
`tcp+udp://` upstream, dae retries after any UDP failure. For dae's own lookups
that a `sub()`, `node()` or `subnode()` rule sends to a `udp://` upstream, dae
does not retry: a truncated answer fails the lookup with
`internal dns response truncated`. For those lookups, dae retries over TCP only
with a `tcp+udp://` upstream. When large answers are expected, name a
`tcp+udp://` or `tcp://` upstream in those rules.

The built-in `asis` destination keeps the address and port the client used,
not the client's transport: dae always queries that server over UDP, even when
the client asked over TCP. `asis` does not retry over TCP. When that server
answers with `TC=1`, dae discards the server's response and replies with a
message built from the client's query: same ID and question, `NOERROR`, `RA=1`,
`TC=1`, empty Answer section. The client then decides whether to retry over
TCP. Every other scheme keeps its declared transport.

## Examples

```shell
dns {
    # For example, if ipversion_prefer is 4 and dae already knows the domain has type A records, dae returns an empty
    # answer to type AAAA queries; otherwise dae returns the AAAA answer unchanged.
    ipversion_prefer: 4

    # Give a fixed ttl for domains. Zero makes the cached answer expire immediately; with optimistic_cache (default true)
    # dae may still serve it as a stale answer while refreshing.
    fixed_domain_ttl {
        ddns.example.org: 10
        test.example.org: 3600
    }

    # Bind to local address to listen for DNS queries
    #bind: '127.0.0.1:5353'

    upstream {
        # Scheme list: tcp, udp, tcp+udp, https, tls, http3, h3, quic, details see above Schema.
        # If host is a domain and has both IPv4 and IPv6 record, dae will automatically choose
        # IPv4 or IPv6 to use according to group policy (such as min latency policy).
        # Please make sure DNS traffic will go through and be forwarded by dae, which is REQUIRED for domain routing.
        # If dial_mode is "ip", the upstream DNS answer SHOULD NOT be polluted, so domestic public DNS is not recommended.

        alidns: 'udp://dns.alidns.com:53'
        googledns: 'tcp+udp://dns.google:53'

        # alih3: 'h3://dns.alidns.com:443'
        # alih3_path: 'h3://dns.alidns.com:443/dns-query'
        # alihttp3: 'http3://dns.alidns.com:443'
        # alihttp3_path: 'http3://dns.alidns.com:443/dns-query'
        # ali_quic: 'quic://dns.alidns.com:853'

        # h3_custom_path: 'h3://dns.example.com:443/custom-path'
        # http3_custom_path: 'http3://dns.example.com:443/custom-path'

        # ali_doh: 'https://dns.alidns.com:443'
        # ali_dot: 'tls://dns.alidns.com:853'

        # doh_custom_path: 'https://dns.example.com:443/custom-path'
    }
    # The routing format of 'request' and 'response' is similar with section 'routing'.
    # See https://github.com/daeuniverse/dae/blob/main/docs/en/configuration/routing.md
    routing {
        # According to the request of dns query, decide to use which DNS upstream.
        # Match rules from top to bottom.
        request {
            # Built-in outbounds in 'request': asis, reject.
            # asis queries the server the request was addressed to, always over UDP.
            # Do not point other LAN devices at dae:53 (loop risk).
            # You can also use user-defined upstreams.

            # Available functions for ordinary DNS requests: qname, qtype.
            # Additional internal dae selectors in the same block: sub, node, subnode.
            # - sub(): subscription fetch requests
            # - node(): node host resolution requests
            # - subnode(): node host resolution requests for subscription-derived nodes
            #   and it is checked before node()
            # Internal selectors:
            # - only affect dae's own DNS lookups
            # - must target names defined in dns.upstream
            # - do not use fallback
            # - cannot be mixed with qname/qtype in the same rule

            # DNS request name (omit suffix dot '.').
            qname(geosite:category-ads-all) -> reject
            qname(geosite:google@cn) -> alidns # Also see: https://github.com/v2fly/domain-list-community#attributes
            qname(suffix: abc.com, keyword: google) -> googledns
            qname(full: ok.com, regex: '^yes') -> googledns
            # DNS request type
            qtype(a, aaaa) -> alidns
            qtype(cname) -> googledns
            # disable ECH to avoid affecting traffic split
            qtype(https) -> reject

            # Route dae's own subscription fetch DNS to googledns.
            # sub(my_sub) -> googledns
            # Route all nodes with "hk" in their name to googledns.
            # node(name_keyword: hk) -> googledns
            # Use alidns for nodes from subscription "my_sub" before node() rules are checked.
            # subnode(subtag: my_sub) -> alidns

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
            ip(geoip:private) && !qname(geosite:cn) -> googledns
            fallback: accept
        }
    }

}
```

`ipversion_prefer` never makes dae send its own query for the preferred family.
With `ipversion_prefer: 4`, dae replaces an `AAAA` answer with an empty
`NOERROR` reply only when it already knows the name has `A` records. dae knows
this when an unexpired cached `A` answer exists, or when an `A` answer with
records arrives while the `AAAA` answer waits up to 50 ms (the RFC 8305
resolution delay). Otherwise dae returns the `AAAA` answer unchanged.
`ipversion_prefer: 6` works the same way with the families swapped.

A `fixed_domain_ttl` of `0` does not disable caching. dae still stores the
answer, with its cache deadline set to the time it was received, so the entry
is expired on the next lookup. `optimistic_cache` defaults to `true`, so dae
answers later queries from that stale entry within `optimistic_cache_ttl`
(default `60` seconds; `0` means no limit) while one background refresh queries
upstream. Record TTLs in those answers are bounded by
`optimistic_stale_reply_ttl` (default `30`). Set `optimistic_cache: false` to
send every query for that domain to upstream synchronously.

## Bootstrap resolver (`global`)

dae queries `global.bootstrap_resolver` directly, never through a proxy, for
three kinds of lookups. The first is the hostname of any `dns.upstream` entry
that is not an IP literal. The second is the background probe that
`dial_mode: domain` (the default) runs for a sniffed domain that has no `A` or
`AAAA` record in dae's DNS cache. `domain+` and `domain++` skip that probe, and
`ip` never dials by domain. `dial_mode` accepts only `ip`, `domain`, `domain+`
and `domain++`. The third applies when `dns.routing.request` contains any rule,
which enables dae's internal DNS router. When no `sub()`, `node()` or
`subnode()` rule assigns the subscription URL host or a node's server hostname
to an upstream, or when the assigned upstream returns no address, dae resolves
that hostname through the bootstrap resolver. These lookups bypass the `qname`
and `qtype` rules and happen while DNS routing is running, not only at startup.

If the option is unset, dae falls back to `119.29.29.29:53` and then
`223.5.5.5:53`. Setting it replaces both defaults; dae uses only the configured
resolver. For a host outside mainland China, a closer resolver is usually preferable:

```shell
global {
  bootstrap_resolver: '9.9.9.9:53'
}
```

## Templates

```shell
# Use alidns for China mainland domains and googledns for others.
dns {
  upstream {
    googledns: 'tcp+udp://dns.google:53'
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
    googledns: 'tcp+udp://dns.google:53'
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
      ip(geoip:private) && !qname(geosite:cn) -> googledns
      # fallback is also called default.
      fallback: accept
    }
  }
}
```
