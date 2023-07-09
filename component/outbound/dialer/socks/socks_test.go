/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2023, daeuniverse Organization <dae@v2raya.org>
 */

package socks

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func TestSocks5(t *testing.T) {
	c, err := ParseSocksURL("socks5://192.168.31.6:1081")
	if err != nil {
		t.Fatal(err)
	}
	log := logrus.StandardLogger()
	d, err := c.Dialer(&dialer.GlobalOption{
		Log: log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{
			Log:             log,
			Raw:             []string{"http://gstatic.com/generate_204"},
			ResolverNetwork: "udp",
			Method:          "HEAD",
		},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{
			Raw:             []string{"dns.google.com:53"},
			ResolverNetwork: "udp",
		},
		CheckInterval:     10 * time.Second,
		CheckTolerance:    0,
		CheckDnsTcp:       true,
		AllowInsecure:     false,
		TlsImplementation: "",
		UtlsImitate:       "",
	}, dialer.InstanceOption{
		CheckEnabled: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := netutils.ResolveNetip(ctx, d, netip.MustParseAddrPort("8.8.8.8:53"), "apple.com", dnsmessage.TypeA, "udp")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(addrs)
}
