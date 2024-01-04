/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

package config_parser

import "testing"

func TestParse(t *testing.T) {
	sections, err := Parse(`
# gugu
include {
    another.conf
}

global {
    # tproxy port to listen.
    tproxy_port: 12345

    # Node connectivity check url.
    check_url: 'https://connectivitycheck.gstatic.com/generate_204'

    # Now only support UDP and IP:Port.
    # Please make sure DNS traffic will go through and be forwarded by dae.
    dns_upstream: '1.1.1.1:53'

    # Now only support one interface.
    ingress_interface: docker0
}

# subscription will be resolved as nodes and merged into node pool below.
subscription {
    https://LINK
}

node {
    'ss://LINK'
    'ssr://LINK'
    'vmess://LINK'
    'vless://LINK'
    'trojan://LINK'
    'trojan-go://LINK'
    'socks5://LINK#name'
    'http://LINK#name'
    'https://LINK#name'
}

group {
    my_group {
        # Pass node links as input of lua script filter.
        # gugu
        filter: link(lua:filename.lua)

        # Randomly select a node from the group for every connection.
        policy: random
    }

    disney {
        # Pass node names as input of keyword/regex filter.
        filter: name(regex:'^.*hk.*$', keyword:'sg') && name(keyword:'disney')

        # Select the node with min average of the last 10 latencies from the group for every connection.
        policy: min_avg10
    }

    netflix {
        # Pass node names as input of keyword filter.
        filter: name(keyword:netflix)

        # Select the first node from the group for every connection.
        policy: fixed(0)
    }
}

routing {
    sip(192.168.0.0/24) && !sip(192.168.0.252/30) -> direct

    domain(geosite:category-ads) -> block
    domain(geosite:disney) -> disney
    domain(geosite:netflix) -> netflix
    ip(geoip:cn) -> direct
    domain(geosite:cn) -> direct
    fallback: my_group
}
`)
	if err != nil {
		t.Fatalf("\n%v", err)
	}
	for _, section := range sections {
		t.Logf("\n%v", section.String(false, false))
	}
}
