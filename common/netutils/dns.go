/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, mzz2017 <mzz@tuta.io>
 */

package netutils

import (
	"context"
	"fmt"
	"github.com/mzz2017/softwind/pkg/fastrand"
	"github.com/mzz2017/softwind/pool"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/proxy"
	"math"
	"net/netip"
	"strings"
	"sync"
	"time"
)

var (
	systemDnsMu sync.Mutex
	systemDns   netip.AddrPort
)

func SystemDns() (dns netip.AddrPort, err error) {
	systemDnsMu.Lock()
	defer systemDnsMu.Unlock()
	if !systemDns.IsValid() {
		dnsConf := dnsReadConfig("/etc/resolv.conf")
		if len(dnsConf.servers) == 0 {
			err = fmt.Errorf("no valid dns server in /etc/resolv.conf")
			return netip.AddrPort{}, err
		}
		systemDns = netip.MustParseAddrPort(dnsConf.servers[0])
	}
	return systemDns, nil
}

func ResolveNetip(ctx context.Context, d proxy.Dialer, dns netip.AddrPort, host string, typ dnsmessage.Type) (addrs []netip.Addr, err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if addr, err := netip.ParseAddr(host); err == nil {
		if (addr.Is4() || addr.Is4In6()) && typ == dnsmessage.TypeA {
			return []netip.Addr{addr}, nil
		} else if addr.Is6() && typ == dnsmessage.TypeAAAA {
			return []netip.Addr{addr}, nil
		}
		return nil, nil
	}
	switch typ {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
	default:
		return nil, fmt.Errorf("only support to lookup A/AAAA record")
	}
	// Build DNS req.
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:               uint16(fastrand.Intn(math.MaxUint16 + 1)),
		Response:         false,
		OpCode:           0,
		Truncated:        false,
		RecursionDesired: true,
		Authoritative:    false,
	})
	if err = builder.StartQuestions(); err != nil {
		return nil, err
	}
	fqdn := host
	if !strings.HasSuffix(fqdn, ".") {
		fqdn += "."
	}
	if err = builder.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName(fqdn),
		Type:  typ,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		return nil, err
	}
	b, err := builder.Finish()
	if err != nil {
		return nil, err
	}

	// Dial and write.
	cd := ContextDialer{d}
	c, err := cd.DialContext(ctx, "udp", dns.String())
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_, err = c.Write(b)
	if err != nil {
		return nil, err
	}
	ch := make(chan error, 2)
	go func() {
		// Resend every 3 seconds.
		for {
			select {
			case <-ctx.Done():
				return
			default:
				time.Sleep(3 * time.Second)
			}
			_, err := c.Write(b)
			if err != nil {
				ch <- err
				return
			}
		}
	}()
	go func() {
		buf := pool.Get(512)
		n, err := c.Read(buf)
		if err != nil {
			ch <- err
			return
		}
		// Resolve DNS response and extract A/AAAA record.
		var msg dnsmessage.Message
		if err = msg.Unpack(buf[:n]); err != nil {
			ch <- err
			return
		}
		for _, ans := range msg.Answers {
			if ans.Header.Type != typ {
				continue
			}
			switch typ {
			case dnsmessage.TypeA:
				a := ans.Body.(*dnsmessage.AResource)
				addrs = append(addrs, netip.AddrFrom4(a.A))
			case dnsmessage.TypeAAAA:
				a := ans.Body.(*dnsmessage.AAAAResource)
				addrs = append(addrs, netip.AddrFrom16(a.AAAA))
			}
		}
		ch <- nil
	}()
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("timeout")
	case err = <-ch:
		if err != nil {
			return nil, err
		}
		return addrs, nil
	}
}
