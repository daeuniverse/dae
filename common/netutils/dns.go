/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, mzz2017 <mzz@tuta.io>
 */

package netutils

import (
	"context"
	"encoding/binary"
	"fmt"
	"github.com/mzz2017/softwind/netproxy"
	"github.com/mzz2017/softwind/pkg/fastrand"
	"github.com/mzz2017/softwind/pool"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"math"
	"net/netip"
	"strings"
	"sync"
	"time"
)

var (
	systemDnsMu              sync.Mutex
	systemDns                netip.AddrPort
	systemDnsNextUpdateAfter time.Time
)

func TryUpdateSystemDns() (err error) {
	systemDnsMu.Lock()
	err = tryUpdateSystemDns()
	systemDnsMu.Unlock()
	return err
}

// TryUpdateSystemDns1s will update system DNS if 1 second has elapsed since the last TryUpdateSystemDns1s call.
func TryUpdateSystemDns1s() (err error) {
	systemDnsMu.Lock()
	defer systemDnsMu.Unlock()
	if time.Now().Before(systemDnsNextUpdateAfter) {
		return fmt.Errorf("update too quickly")
	}
	err = tryUpdateSystemDns()
	if err != nil {
		return err
	}
	systemDnsNextUpdateAfter = time.Now().Add(time.Second)
	return nil
}

func tryUpdateSystemDns() (err error) {
	dnsConf := dnsReadConfig("/etc/resolv.conf")
	if len(dnsConf.servers) == 0 {
		err = fmt.Errorf("no valid dns server in /etc/resolv.conf")
		return err
	}
	systemDns = netip.MustParseAddrPort(dnsConf.servers[0])
	return nil
}

func SystemDns() (dns netip.AddrPort, err error) {
	systemDnsMu.Lock()
	defer systemDnsMu.Unlock()
	if !systemDns.IsValid() {
		if err = tryUpdateSystemDns(); err != nil {
			return netip.AddrPort{}, err
		}
	}
	return systemDns, nil
}

func ResolveNetip(ctx context.Context, d netproxy.Dialer, dns netip.AddrPort, host string, typ dnsmessage.Type, tcp bool) (addrs []netip.Addr, err error) {
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
	if tcp {
		buf := pool.Get(2 + len(b))
		defer pool.Put(buf)
		binary.BigEndian.PutUint16(buf, uint16(len(b)))
		copy(buf[2:], b)
		b = buf
	}

	// Dial and write.
	cd := &netproxy.ContextDialer{Dialer: d}
	var c netproxy.Conn
	if tcp {
		c, err = cd.DialTcpContext(ctx, dns.String())
	} else {
		c, err = cd.DialUdpContext(ctx, dns.String())
	}
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_, err = c.Write(b)
	if err != nil {
		return nil, err
	}
	ch := make(chan error, 2)
	if !tcp {
		go func() {
			// Resend every 3 seconds for UDP.
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
	}
	go func() {
		buf := pool.Get(512)
		defer pool.Put(buf)
		if tcp {
			_, err := io.ReadFull(c, buf[:2])
			if err != nil {
				ch <- err
				return
			}
			n := binary.BigEndian.Uint16(buf)
			if n > 512 {
				ch <- fmt.Errorf("too big dns resp")
				return
			}
			buf = buf[:n]
		}
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
