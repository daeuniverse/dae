/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package netutils

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net/netip"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/softwind/netproxy"
	"github.com/daeuniverse/softwind/pkg/fastrand"
	"github.com/daeuniverse/softwind/pool"
	dnsmessage "github.com/miekg/dns"
)

var (
	systemDnsMu              sync.Mutex
	systemDns                netip.AddrPort
	systemDnsNextUpdateAfter time.Time

	BadDnsAnsError = fmt.Errorf("bad dns answer")

	BootstrapDns = netip.MustParseAddrPort("208.67.222.222:5353")
)

func TryUpdateSystemDns() (err error) {
	systemDnsMu.Lock()
	err = tryUpdateSystemDns()
	systemDnsMu.Unlock()
	return err
}

// TryUpdateSystemDnsElapse will update system DNS if duration has elapsed since the last TryUpdateSystemDns1s call.
func TryUpdateSystemDnsElapse(k time.Duration) (err error) {
	systemDnsMu.Lock()
	defer systemDnsMu.Unlock()
	return tryUpdateSystemDnsElapse(k)
}
func tryUpdateSystemDnsElapse(k time.Duration) (err error) {
	if time.Now().Before(systemDnsNextUpdateAfter) {
		return fmt.Errorf("update too quickly")
	}
	err = tryUpdateSystemDns()
	if err != nil {
		return err
	}
	systemDnsNextUpdateAfter = time.Now().Add(k)
	return nil
}

func tryUpdateSystemDns() (err error) {
	dnsConf := dnsReadConfig("/etc/resolv.conf")
	if len(dnsConf.servers) == 0 {
		err = fmt.Errorf("no valid dns server in /etc/resolv.conf")
		return err
	}
	systemDns = netip.AddrPort{}
	for _, s := range dnsConf.servers {
		ipPort := netip.MustParseAddrPort(s)
		if !ipPort.Addr().IsLoopback() {
			systemDns = ipPort
			break
		}
	}
	if !systemDns.IsValid() {
		systemDns = BootstrapDns
	}
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
	// To avoid environment changing.
	_ = tryUpdateSystemDnsElapse(5 * time.Second)
	return systemDns, nil
}

func ResolveNetip(ctx context.Context, d netproxy.Dialer, dns netip.AddrPort, host string, typ uint16, network string) (addrs []netip.Addr, err error) {
	resources, err := resolve(ctx, d, dns, host, typ, network)
	if err != nil {
		return nil, err
	}
	for _, ans := range resources {
		if ans.Header().Rrtype != typ {
			continue
		}
		var (
			ip  netip.Addr
			okk bool
		)
		switch typ {
		case dnsmessage.TypeA:
			a, ok := ans.(*dnsmessage.A)
			if !ok {
				return nil, BadDnsAnsError
			}
			ip, okk = netip.AddrFromSlice(a.A)
		case dnsmessage.TypeAAAA:
			a, ok := ans.(*dnsmessage.AAAA)
			if !ok {
				return nil, BadDnsAnsError
			}
			ip, okk = netip.AddrFromSlice(a.AAAA)
		}
		if !okk {
			continue
		}
		addrs = append(addrs, ip)
	}
	return addrs, nil
}

func ResolveNS(ctx context.Context, d netproxy.Dialer, dns netip.AddrPort, host string, network string) (records []string, err error) {
	typ := dnsmessage.TypeNS
	resources, err := resolve(ctx, d, dns, host, typ, network)
	if err != nil {
		return nil, err
	}
	for _, ans := range resources {
		if ans.Header().Rrtype != typ {
			continue
		}
		ns, ok := ans.(*dnsmessage.NS)
		if !ok {
			return nil, BadDnsAnsError
		}
		records = append(records, ns.Ns)
	}
	return records, nil
}

func resolve(ctx context.Context, d netproxy.Dialer, dns netip.AddrPort, host string, typ uint16, network string) (ans []dnsmessage.RR, err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	fqdn := dnsmessage.CanonicalName(host)
	switch typ {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
		if addr, err := netip.ParseAddr(host); err == nil {
			if (addr.Is4() || addr.Is4In6()) && typ == dnsmessage.TypeA {
				return []dnsmessage.RR{
					&dnsmessage.A{
						Hdr: dnsmessage.RR_Header{
							Name:   dnsmessage.CanonicalName(fqdn),
							Class:  dnsmessage.ClassINET,
							Ttl:    0,
							Rrtype: typ,
						},
						A: addr.AsSlice(),
					},
				}, nil
			} else if addr.Is6() && typ == dnsmessage.TypeAAAA {
				return []dnsmessage.RR{
					&dnsmessage.AAAA{
						Hdr: dnsmessage.RR_Header{
							Name:   dnsmessage.CanonicalName(fqdn),
							Class:  dnsmessage.ClassINET,
							Ttl:    0,
							Rrtype: typ,
						},
						AAAA: addr.AsSlice(),
					},
				}, nil
			}
			// MUST No record.
			return nil, nil
		}
	default:
	}
	// Build DNS req.
	builder := dnsmessage.Msg{
		MsgHdr: dnsmessage.MsgHdr{
			Id:               uint16(fastrand.Intn(math.MaxUint16 + 1)),
			Response:         false,
			Opcode:           0,
			Truncated:        false,
			RecursionDesired: true,
			Authoritative:    false,
		},
	}
	builder.SetQuestion(fqdn, typ)
	b, err := builder.Pack()
	if err != nil {
		return nil, err
	}
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	if magicNetwork.Network == "tcp" {
		// Put DNS request length
		buf := pool.Get(2 + len(b))
		defer pool.Put(buf)
		binary.BigEndian.PutUint16(buf, uint16(len(b)))
		copy(buf[2:], b)
		b = buf
	}

	// Dial and write.
	cd := &netproxy.ContextDialerConverter{Dialer: d}
	c, err := cd.DialContext(ctx, network, dns.String())
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_, err = c.Write(b)
	if err != nil {
		return nil, err
	}
	ch := make(chan error, 2)
	if magicNetwork.Network == "udp" {
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
		buf := pool.GetFullCap(consts.EthernetMtu)
		defer buf.Put()
		if magicNetwork.Network == "tcp" {
			// Read DNS response length
			_, err := io.ReadFull(c, buf[:2])
			if err != nil {
				ch <- err
				return
			}
			n := binary.BigEndian.Uint16(buf)
			if int(n) > cap(buf) {
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
		var msg dnsmessage.Msg
		if err = msg.Unpack(buf[:n]); err != nil {
			ch <- err
			return
		}
		ans = msg.Answer
		ch <- nil
	}()
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("timeout")
	case err = <-ch:
		if err != nil {
			return nil, err
		}
		return ans, nil
	}
}
