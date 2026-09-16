/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
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
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	dnsmessage "github.com/miekg/dns"
)

var ErrBadDnsAns = fmt.Errorf("bad dns answer")

const maxDNSMessageSize = 65535

type dnsResolveResult struct {
	ans []dnsmessage.RR
	err error
}

// SystemDNSResolver caches the host resolver independently for one runtime generation.
type SystemDNSResolver struct {
	mu              sync.Mutex
	dns             netip.AddrPort
	nextUpdateAfter time.Time
	fallback        netip.AddrPort
	readConfig      func(string) *dnsConfig
}

// NewSystemDNSResolver creates a generation-scoped system DNS resolver.
func NewSystemDNSResolver(fallback netip.AddrPort) *SystemDNSResolver {
	return &SystemDNSResolver{fallback: fallback, readConfig: dnsReadConfig}
}

// TryUpdateElapse updates the cached system DNS if the minimum interval elapsed.
func (r *SystemDNSResolver) TryUpdateElapse(k time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.tryUpdateElapse(k)
}

func (r *SystemDNSResolver) tryUpdateElapse(k time.Duration) error {
	if time.Now().Before(r.nextUpdateAfter) {
		return fmt.Errorf("update too quickly")
	}
	if err := r.update(); err != nil {
		return err
	}
	r.nextUpdateAfter = time.Now().Add(k)
	return nil
}

func (r *SystemDNSResolver) update() error {
	readConfig := r.readConfig
	if readConfig == nil {
		readConfig = dnsReadConfig
	}
	dnsConf := readConfig("/etc/resolv.conf")
	r.dns = netip.AddrPort{}
	for _, s := range dnsConf.servers {
		ipPort := netip.MustParseAddrPort(s)
		if !ipPort.Addr().IsLoopback() {
			r.dns = ipPort
			break
		}
	}
	if !r.dns.IsValid() {
		r.dns = r.fallback
	}
	return nil
}

// SystemDNS returns the current generation's cached system DNS server.
func (r *SystemDNSResolver) SystemDNS() (netip.AddrPort, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.dns.IsValid() {
		if err := r.update(); err != nil {
			return netip.AddrPort{}, err
		}
	}
	// Refresh periodically so environment changes are eventually observed.
	_ = r.tryUpdateElapse(5 * time.Second)
	return r.dns, nil
}

var defaultSystemDNSResolver = NewSystemDNSResolver(netip.AddrPort{})

// TryUpdateSystemDnsElapse updates the process-default resolver for compatibility.
func TryUpdateSystemDnsElapse(k time.Duration) error {
	return defaultSystemDNSResolver.TryUpdateElapse(k)
}

// SystemDns returns the process-default resolver for compatibility.
func SystemDns() (netip.AddrPort, error) {
	return defaultSystemDNSResolver.SystemDNS()
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
				return nil, ErrBadDnsAns
			}
			ip, okk = netip.AddrFromSlice(a.A)
		case dnsmessage.TypeAAAA:
			a, ok := ans.(*dnsmessage.AAAA)
			if !ok {
				return nil, ErrBadDnsAns
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

func resolve(ctx context.Context, d netproxy.Dialer, dns netip.AddrPort, host string, typ uint16, network string) ([]dnsmessage.RR, error) {
	if d == nil {
		return nil, fmt.Errorf("nil dialer")
	}
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
	c, err := d.DialContext(ctx, network, dns.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	if magicNetwork.Network == "udp" {
		_, err = WriteUDPConn(c, dns.String(), b)
	} else {
		_, err = c.Write(b)
	}
	if err != nil {
		return nil, err
	}
	ch := make(chan dnsResolveResult, 2)
	if magicNetwork.Network == "udp" {
		go func() {
			// Resend every 3 seconds for UDP.
			ticker := time.NewTicker(3 * time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					_, err := WriteUDPConn(c, dns.String(), b)
					if err != nil {
						ch <- dnsResolveResult{err: err}
						return
					}
				}
			}
		}()
	}
	go func() {
		if magicNetwork.Network == "tcp" {
			var header [2]byte
			// Read DNS response length
			if _, err := io.ReadFull(c, header[:]); err != nil {
				ch <- dnsResolveResult{err: err}
				return
			}
			msgLen := int(binary.BigEndian.Uint16(header[:]))
			if msgLen <= 0 || msgLen > maxDNSMessageSize {
				ch <- dnsResolveResult{err: fmt.Errorf("invalid dns resp size: %d", msgLen)}
				return
			}
			buf := pool.GetFullCap(msgLen)
			defer buf.Put()
			if _, err := io.ReadFull(c, buf[:msgLen]); err != nil {
				ch <- dnsResolveResult{err: err}
				return
			}
			ch <- decodeResolvedAnswer(buf[:msgLen], builder.Id)
			return
		}

		buf := pool.GetFullCap(consts.EthernetMtu)
		defer buf.Put()
		n, err := ReadUDPConn(c, buf)
		if err != nil {
			ch <- dnsResolveResult{err: err}
			return
		}
		ch <- decodeResolvedAnswer(buf[:n], builder.Id)
	}()
	select {
	case <-ctx.Done():
		// Wrap ctx.Err() so callers can distinguish cancellation from a
		// real deadline via errors.Is while the message stays readable.
		return nil, fmt.Errorf("timeout: %w", ctx.Err())
	case res := <-ch:
		if res.err != nil {
			return nil, res.err
		}
		return res.ans, nil
	}
}

func decodeResolvedAnswer(payload []byte, expectedID uint16) dnsResolveResult {
	var msg dnsmessage.Msg
	if err := msg.Unpack(payload); err != nil {
		return dnsResolveResult{err: err}
	}

	if msg.Id != expectedID {
		return dnsResolveResult{err: fmt.Errorf("id mismatch: expect %v, got %v", expectedID, msg.Id)}
	}

	// Copy RRs before returning so callers don't retain pooled memory indirectly.
	var ans []dnsmessage.RR
	if len(msg.Answer) > 0 {
		ans = make([]dnsmessage.RR, len(msg.Answer))
		for i, rr := range msg.Answer {
			ans[i] = dnsmessage.Copy(rr)
		}
	}
	return dnsResolveResult{ans: ans}
}
