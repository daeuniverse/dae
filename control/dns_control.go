/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
	dnsmessage "github.com/miekg/dns"
	"github.com/mohae/deepcopy"
	"github.com/sirupsen/logrus"
)

const (
	MaxDnsLookupDepth  = 3
	minFirefoxCacheTtl = 120
)

type IpVersionPrefer int

const (
	IpVersionPrefer_No IpVersionPrefer = 0
	IpVersionPrefer_4  IpVersionPrefer = 4
	IpVersionPrefer_6  IpVersionPrefer = 6
)

var (
	ErrUnsupportedQuestionType = fmt.Errorf("unsupported question type")
)

var (
	UnspecifiedAddressA    = netip.MustParseAddr("0.0.0.0")
	UnspecifiedAddressAAAA = netip.MustParseAddr("::")
)

type DnsControllerOption struct {
	Log                   *logrus.Logger
	CacheAccessCallback   func(cache *DnsCache) (err error)
	CacheRemoveCallback   func(cache *DnsCache) (err error)
	NewCache              func(fqdn string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (cache *DnsCache, err error)
	BestDialerChooser     func(req *udpRequest, upstream *dns.Upstream) (*dialArgument, error)
	TimeoutExceedCallback func(dialArgument *dialArgument, err error)
	IpVersionPrefer       int
	FixedDomainTtl        map[string]int
}

type DnsController struct {
	handling sync.Map

	routing     *dns.Dns
	qtypePrefer uint16

	log                 *logrus.Logger
	cacheAccessCallback func(cache *DnsCache) (err error)
	cacheRemoveCallback func(cache *DnsCache) (err error)
	newCache            func(fqdn string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (cache *DnsCache, err error)
	bestDialerChooser   func(req *udpRequest, upstream *dns.Upstream) (*dialArgument, error)
	// timeoutExceedCallback is used to report this dialer is broken for the NetworkType
	timeoutExceedCallback func(dialArgument *dialArgument, err error)

	fixedDomainTtl map[string]int
	// mutex protects the dnsCache.
	dnsCacheMu sync.Mutex
	dnsCache   map[string]*DnsCache
}

func parseIpVersionPreference(prefer int) (uint16, error) {
	switch prefer := IpVersionPrefer(prefer); prefer {
	case IpVersionPrefer_No:
		return 0, nil
	case IpVersionPrefer_4:
		return dnsmessage.TypeA, nil
	case IpVersionPrefer_6:
		return dnsmessage.TypeAAAA, nil
	default:
		return 0, fmt.Errorf("unknown preference: %v", prefer)
	}
}

func NewDnsController(routing *dns.Dns, option *DnsControllerOption) (c *DnsController, err error) {
	// Parse ip version preference.
	prefer, err := parseIpVersionPreference(option.IpVersionPrefer)
	if err != nil {
		return nil, err
	}

	return &DnsController{
		routing:     routing,
		qtypePrefer: prefer,

		log:                   option.Log,
		cacheAccessCallback:   option.CacheAccessCallback,
		cacheRemoveCallback:   option.CacheRemoveCallback,
		newCache:              option.NewCache,
		bestDialerChooser:     option.BestDialerChooser,
		timeoutExceedCallback: option.TimeoutExceedCallback,

		fixedDomainTtl: option.FixedDomainTtl,
		dnsCacheMu:     sync.Mutex{},
		dnsCache:       make(map[string]*DnsCache),
	}, nil
}

func (c *DnsController) cacheKey(qname string, qtype uint16) string {
	// To fqdn.
	return dnsmessage.CanonicalName(qname) + strconv.Itoa(int(qtype))
}

func (c *DnsController) RemoveDnsRespCache(cacheKey string) {
	c.dnsCacheMu.Lock()
	_, ok := c.dnsCache[cacheKey]
	if ok {
		delete(c.dnsCache, cacheKey)
	}
	c.dnsCacheMu.Unlock()
}
func (c *DnsController) LookupDnsRespCache(cacheKey string, ignoreFixedTtl bool) (cache *DnsCache) {
	c.dnsCacheMu.Lock()
	cache, ok := c.dnsCache[cacheKey]
	c.dnsCacheMu.Unlock()
	if !ok {
		return nil
	}
	var deadline time.Time
	if !ignoreFixedTtl {
		deadline = cache.Deadline
	} else {
		deadline = cache.OriginalDeadline
	}
	// We should make sure the cache did not expire, or
	// return nil and request a new lookup to refresh the cache.
	if !deadline.After(time.Now()) {
		return nil
	}
	if err := c.cacheAccessCallback(cache); err != nil {
		c.log.Warnf("failed to BatchUpdateDomainRouting: %v", err)
		return nil
	}
	return cache
}

// LookupDnsRespCache_ will modify the msg in place.
func (c *DnsController) LookupDnsRespCache_(msg *dnsmessage.Msg, cacheKey string, ignoreFixedTtl bool) (resp []byte) {
	cache := c.LookupDnsRespCache(cacheKey, ignoreFixedTtl)
	if cache != nil {
		cache.FillInto(msg)
		msg.Compress = true
		b, err := msg.Pack()
		if err != nil {
			c.log.Warnf("failed to pack: %v", err)
			return nil
		}
		return b
	}
	return nil
}

// NormalizeAndCacheDnsResp_ handle DNS resp in place.
func (c *DnsController) NormalizeAndCacheDnsResp_(msg *dnsmessage.Msg) (err error) {
	// Check healthy resp.
	if !msg.Response || len(msg.Question) == 0 {
		return nil
	}

	q := msg.Question[0]

	// Check suc resp.
	if msg.Rcode != dnsmessage.RcodeSuccess {
		return nil
	}

	// Get TTL.
	var ttl uint32
	for i := range msg.Answer {
		if ttl == 0 {
			ttl = msg.Answer[i].Header().Ttl
			break
		}
	}
	if ttl == 0 {
		// It seems no answers (NXDomain).
		ttl = minFirefoxCacheTtl
	}

	// Check req type.
	switch q.Qtype {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
	default:
		// Update DnsCache.
		if err = c.updateDnsCache(msg, ttl, &q); err != nil {
			return err
		}
		return nil
	}

	// Set ttl.
	for i := range msg.Answer {
		// Set TTL = zero. This requests applications must resend every request.
		// However, it may be not defined in the standard.
		msg.Answer[i].Header().Ttl = 0
	}

	// Check if request A/AAAA record.
	var reqIpRecord bool
loop:
	for i := range msg.Question {
		switch msg.Question[i].Qtype {
		case dnsmessage.TypeA, dnsmessage.TypeAAAA:
			reqIpRecord = true
			break loop
		}
	}
	if !reqIpRecord {
		// Update DnsCache.
		if err = c.updateDnsCache(msg, ttl, &q); err != nil {
			return err
		}
		return nil
	}

	// Update DnsCache.
	if err = c.updateDnsCache(msg, ttl, &q); err != nil {
		return err
	}
	// Pack to get newData.
	return nil
}

func (c *DnsController) updateDnsCache(msg *dnsmessage.Msg, ttl uint32, q *dnsmessage.Question) error {
	// Update DnsCache.
	if c.log.IsLevelEnabled(logrus.TraceLevel) {
		c.log.WithFields(logrus.Fields{
			"_qname": q.Name,
			"rcode":  msg.Rcode,
			"ans":    FormatDnsRsc(msg.Answer),
		}).Tracef("Update DNS record cache")
	}

	if err := c.UpdateDnsCacheTtl(q.Name, q.Qtype, msg.Answer, int(ttl)); err != nil {
		return err
	}
	return nil
}

type daedlineFunc func(now time.Time, host string) (deadline time.Time, originalDeadline time.Time)

func (c *DnsController) __updateDnsCacheDeadline(host string, dnsTyp uint16, answers []dnsmessage.RR, deadlineFunc daedlineFunc) (err error) {
	var fqdn string
	if strings.HasSuffix(host, ".") {
		fqdn = strings.ToLower(host)
		host = host[:len(host)-1]
	} else {
		fqdn = dnsmessage.CanonicalName(host)
	}
	// Bypass pure IP.
	if _, err = netip.ParseAddr(host); err == nil {
		return nil
	}

	now := time.Now()
	deadline, originalDeadline := deadlineFunc(now, host)

	cacheKey := c.cacheKey(fqdn, dnsTyp)
	c.dnsCacheMu.Lock()
	cache, ok := c.dnsCache[cacheKey]
	if ok {
		cache.Answer = answers
		cache.Deadline = deadline
		cache.OriginalDeadline = originalDeadline
		c.dnsCacheMu.Unlock()
	} else {
		cache, err = c.newCache(fqdn, answers, deadline, originalDeadline)
		if err != nil {
			c.dnsCacheMu.Unlock()
			return err
		}
		c.dnsCache[cacheKey] = cache
		c.dnsCacheMu.Unlock()
	}
	if err = c.cacheAccessCallback(cache); err != nil {
		return err
	}

	return nil
}

func (c *DnsController) UpdateDnsCacheDeadline(host string, dnsTyp uint16, answers []dnsmessage.RR, deadline time.Time) (err error) {
	return c.__updateDnsCacheDeadline(host, dnsTyp, answers, func(now time.Time, host string) (daedline time.Time, originalDeadline time.Time) {
		if fixedTtl, ok := c.fixedDomainTtl[host]; ok {
			/// NOTICE: Cannot set TTL accurately.
			if now.Sub(deadline).Seconds() > float64(fixedTtl) {
				deadline := now.Add(time.Duration(fixedTtl) * time.Second)
				return deadline, deadline
			}
		}
		return deadline, deadline
	})
}

func (c *DnsController) UpdateDnsCacheTtl(host string, dnsTyp uint16, answers []dnsmessage.RR, ttl int) (err error) {
	return c.__updateDnsCacheDeadline(host, dnsTyp, answers, func(now time.Time, host string) (daedline time.Time, originalDeadline time.Time) {
		originalDeadline = now.Add(time.Duration(ttl) * time.Second)
		if fixedTtl, ok := c.fixedDomainTtl[host]; ok {
			return now.Add(time.Duration(fixedTtl) * time.Second), originalDeadline
		} else {
			return originalDeadline, originalDeadline
		}
	})
}

type udpRequest struct {
	realSrc       netip.AddrPort
	realDst       netip.AddrPort
	src           netip.AddrPort
	lConn         *net.UDPConn
	routingResult *bpfRoutingResult
}

type dialArgument struct {
	l4proto      consts.L4ProtoStr
	ipversion    consts.IpVersionStr
	bestDialer   *dialer.Dialer
	bestOutbound *outbound.DialerGroup
	bestTarget   netip.AddrPort
	mark         uint32
	mptcp        bool
}

func (c *DnsController) Handle_(dnsMessage *dnsmessage.Msg, req *udpRequest) (err error) {
	if c.log.IsLevelEnabled(logrus.TraceLevel) && len(dnsMessage.Question) > 0 {
		q := dnsMessage.Question[0]
		c.log.Tracef("Received UDP(DNS) %v <-> %v: %v %v",
			RefineSourceToShow(req.realSrc, req.realDst.Addr()), req.realDst.String(), strings.ToLower(q.Name), QtypeToString(q.Qtype),
		)
	}

	if dnsMessage.Response {
		return fmt.Errorf("DNS request expected but DNS response received")
	}

	// Prepare qname, qtype.
	var qname string
	var qtype uint16
	if len(dnsMessage.Question) != 0 {
		qname = dnsMessage.Question[0].Name
		qtype = dnsMessage.Question[0].Qtype
	}

	// Check ip version preference and qtype.
	switch qtype {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
		if c.qtypePrefer == 0 {
			return c.handle_(dnsMessage, req, true)
		}
	default:
		return c.handle_(dnsMessage, req, true)
	}

	// Try to make both A and AAAA lookups.
	dnsMessage2 := deepcopy.Copy(dnsMessage).(*dnsmessage.Msg)
	dnsMessage2.Id = uint16(fastrand.Intn(math.MaxUint16))
	var qtype2 uint16
	switch qtype {
	case dnsmessage.TypeA:
		qtype2 = dnsmessage.TypeAAAA
	case dnsmessage.TypeAAAA:
		qtype2 = dnsmessage.TypeA
	default:
		return fmt.Errorf("unexpected qtype path")
	}
	dnsMessage2.Question[0].Qtype = qtype2

	done := make(chan struct{})
	go func() {
		_ = c.handle_(dnsMessage2, req, false)
		done <- struct{}{}
	}()
	err = c.handle_(dnsMessage, req, false)
	<-done
	if err != nil {
		return err
	}

	// Join results and consider whether to response.
	resp := c.LookupDnsRespCache_(dnsMessage, c.cacheKey(qname, qtype), true)
	if resp == nil {
		// resp is not valid.
		c.log.WithFields(logrus.Fields{
			"qname": qname,
		}).Tracef("Reject %v due to resp not valid", qtype)
		return c.sendReject_(dnsMessage, req)
	}
	// resp is valid.
	cache2 := c.LookupDnsRespCache(c.cacheKey(qname, qtype2), true)
	if c.qtypePrefer == qtype || cache2 == nil || !cache2.IncludeAnyIp() {
		return sendPkt(c.log, resp, req.realDst, req.realSrc, req.src, req.lConn)
	} else {
		return c.sendReject_(dnsMessage, req)
	}
}

func (c *DnsController) handle_(
	dnsMessage *dnsmessage.Msg,
	req *udpRequest,
	needResp bool,
) (err error) {
	// Prepare qname, qtype.
	var qname string
	var qtype uint16
	if len(dnsMessage.Question) != 0 {
		q := dnsMessage.Question[0]
		qname = q.Name
		qtype = q.Qtype
	}

	// Route request.
	upstreamIndex, upstream, err := c.routing.RequestSelect(qname, qtype)
	if err != nil {
		return err
	}

	cacheKey := c.cacheKey(qname, qtype)

	if upstreamIndex == consts.DnsRequestOutboundIndex_Reject {
		// Reject with empty answer.
		c.RemoveDnsRespCache(cacheKey)
		return c.sendReject_(dnsMessage, req)
	}

	// No parallel for the same lookup.
	_mu, _ := c.handling.LoadOrStore(cacheKey, new(sync.Mutex))
	mu := _mu.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()
	defer c.handling.Delete(cacheKey)

	if resp := c.LookupDnsRespCache_(dnsMessage, cacheKey, false); resp != nil {
		// Send cache to client directly.
		if needResp {
			if err = sendPkt(c.log, resp, req.realDst, req.realSrc, req.src, req.lConn); err != nil {
				return fmt.Errorf("failed to write cached DNS resp: %w", err)
			}
		}
		if c.log.IsLevelEnabled(logrus.DebugLevel) && len(dnsMessage.Question) > 0 {
			q := dnsMessage.Question[0]
			c.log.Debugf("UDP(DNS) %v <-> Cache: %v %v",
				RefineSourceToShow(req.realSrc, req.realDst.Addr()), strings.ToLower(q.Name), QtypeToString(q.Qtype),
			)
		}
		return nil
	}

	if c.log.IsLevelEnabled(logrus.TraceLevel) {
		upstreamName := upstreamIndex.String()
		if upstream != nil {
			upstreamName = upstream.String()
		}
		c.log.WithFields(logrus.Fields{
			"question": dnsMessage.Question,
			"upstream": upstreamName,
		}).Traceln("Request to DNS upstream")
	}

	// Re-pack DNS packet.
	data, err := dnsMessage.Pack()
	if err != nil {
		return fmt.Errorf("pack DNS packet: %w", err)
	}
	return c.dialSend(0, req, data, dnsMessage.Id, upstream, needResp)
}

// sendReject_ send empty answer.
func (c *DnsController) sendReject_(dnsMessage *dnsmessage.Msg, req *udpRequest) (err error) {
	dnsMessage.Answer = nil
	dnsMessage.Rcode = dnsmessage.RcodeSuccess
	dnsMessage.Response = true
	dnsMessage.RecursionAvailable = true
	dnsMessage.Truncated = false
	dnsMessage.Compress = true
	if c.log.IsLevelEnabled(logrus.TraceLevel) {
		c.log.WithFields(logrus.Fields{
			"question": dnsMessage.Question,
		}).Traceln("Reject")
	}
	data, err := dnsMessage.Pack()
	if err != nil {
		return fmt.Errorf("pack DNS packet: %w", err)
	}
	if err = sendPkt(c.log, data, req.realDst, req.realSrc, req.src, req.lConn); err != nil {
		return err
	}
	return nil
}

func (c *DnsController) dialSend(invokingDepth int, req *udpRequest, data []byte, id uint16, upstream *dns.Upstream, needResp bool) (err error) {
	if invokingDepth >= MaxDnsLookupDepth {
		return fmt.Errorf("too deep DNS lookup invoking (depth: %v); there may be infinite loop in your DNS response routing", MaxDnsLookupDepth)
	}

	upstreamName := "asis"
	if upstream == nil {
		// As-is.

		// As-is should not be valid in response routing, thus using connection realDest is reasonable.
		var ip46 netutils.Ip46
		if req.realDst.Addr().Is4() {
			ip46.Ip4 = req.realDst.Addr()
		} else {
			ip46.Ip6 = req.realDst.Addr()
		}
		upstream = &dns.Upstream{
			Scheme:   "udp",
			Hostname: req.realDst.Addr().String(),
			Port:     req.realDst.Port(),
			Ip46:     &ip46,
		}
	} else {
		upstreamName = upstream.String()
	}

	// Select best dial arguments (outbound, dialer, l4proto, ipversion, etc.)
	dialArgument, err := c.bestDialerChooser(req, upstream)
	if err != nil {
		return err
	}

	networkType := &dialer.NetworkType{
		L4Proto:   dialArgument.l4proto,
		IpVersion: dialArgument.ipversion,
		IsDns:     true,
	}

	// Dial and send.
	var respMsg *dnsmessage.Msg
	// defer in a recursive call will delay Close(), thus we Close() before
	// the next recursive call. However, a connection cannot be closed twice.
	// We should set a connClosed flag to avoid it.
	var connClosed bool
	var conn netproxy.Conn

	ctxDial, cancel := context.WithTimeout(context.TODO(), consts.DefaultDialTimeout)
	defer cancel()

	switch dialArgument.l4proto {
	case consts.L4ProtoStr_UDP:
		// Get udp endpoint.

		// TODO: connection pool.
		conn, err = dialArgument.bestDialer.DialContext(
			ctxDial,
			common.MagicNetwork("udp", dialArgument.mark, dialArgument.mptcp),
			dialArgument.bestTarget.String(),
		)
		if err != nil {
			return fmt.Errorf("failed to dial '%v': %w", dialArgument.bestTarget, err)
		}
		defer func() {
			if !connClosed {
				conn.Close()
			}
		}()

		timeout := 5 * time.Second
		_ = conn.SetDeadline(time.Now().Add(timeout))
		dnsReqCtx, cancelDnsReqCtx := context.WithTimeout(context.TODO(), timeout)
		defer cancelDnsReqCtx()
		if upstream.Scheme == "udp" {
			go func() {
				// Send DNS request every seconds.
				for {
					_, err = conn.Write(data)
					if err != nil {
						if c.log.IsLevelEnabled(logrus.DebugLevel) {
							c.log.WithFields(logrus.Fields{
								"to":      dialArgument.bestTarget.String(),
								"pid":     req.routingResult.Pid,
								"pname":   ProcessName2String(req.routingResult.Pname[:]),
								"mac":     Mac2String(req.routingResult.Mac[:]),
								"from":    req.realSrc.String(),
								"network": networkType.String(),
								"err":     err.Error(),
							}).Debugln("Failed to write UDP(DNS) packet request.")
						}
						return
					}
					select {
					case <-dnsReqCtx.Done():
						return
					case <-time.After(1 * time.Second):
					}
				}
			}()

			// We can block here because we are in a coroutine.
			respBuf := pool.GetFullCap(consts.EthernetMtu)
			defer pool.Put(respBuf)
			// Wait for response.
			n, err := conn.Read(respBuf)
			if err != nil {
				if c.timeoutExceedCallback != nil {
					c.timeoutExceedCallback(dialArgument, err)
				}
				return fmt.Errorf("failed to read from: %v (dialer: %v): %w", dialArgument.bestTarget, dialArgument.bestDialer.Property().Name, err)
			}
			var msg dnsmessage.Msg
			if err = msg.Unpack(respBuf[:n]); err != nil {
				return err
			}
			respMsg = &msg
			cancelDnsReqCtx()
		} else if upstream.Scheme == "http3" {
			roundTripper := &http3.RoundTripper{
				TLSClientConfig: &tls.Config{
					ServerName:         upstream.Hostname,
					NextProtos:         []string{"h3"},
					InsecureSkipVerify: false,
				},
				QuicConfig: &quic.Config{},
				Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
					udpAddr := net.UDPAddrFromAddrPort(dialArgument.bestTarget)
					pkt := conn.(netproxy.PacketConn)
					fakePkt := &netproxy.FakeNetPacketConn{
						PacketConn: pkt,
						LAddr: net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr("::1"), 0)),
						RAddr: udpAddr,
					}
					c, e := quic.DialEarly(ctx, fakePkt, udpAddr, tlsCfg, cfg)
					return c, e
				},
			}
			defer roundTripper.Close()

			client := &http.Client{
				Transport: roundTripper,
			}
			msg, err := httpDNS(client, dialArgument.bestTarget.String(), data)
			if err != nil {
				return err
			}
			respMsg = msg
		}

	case consts.L4ProtoStr_TCP:
		// We can block here because we are in a coroutine.

		conn, err = dialArgument.bestDialer.DialContext(ctxDial, common.MagicNetwork("tcp", dialArgument.mark, dialArgument.mptcp), dialArgument.bestTarget.String())
		if upstream.Scheme == "tls" {
			tlsConn := tls.Client(&netproxy.FakeNetConn{Conn: conn}, &tls.Config{
				InsecureSkipVerify: false,
				ServerName:         upstream.Hostname,
			})
			conn = tlsConn
		}
		if err != nil {
			return fmt.Errorf("failed to dial proxy to tcp: %w", err)
		}
		defer func() {
			if !connClosed {
				conn.Close()
			}
		}()

		_ = conn.SetDeadline(time.Now().Add(4900 * time.Millisecond))
		if upstream.Scheme == "tcp" || upstream.Scheme == "tls" {

			// We should write two byte length in the front of TCP DNS request.
			bReq := pool.Get(2 + len(data))
			defer pool.Put(bReq)
			binary.BigEndian.PutUint16(bReq, uint16(len(data)))
			copy(bReq[2:], data)
			_, err = conn.Write(bReq)
			if err != nil {
				return fmt.Errorf("failed to write DNS req: %w", err)
			}

			// Read two byte length.
			if _, err = io.ReadFull(conn, bReq[:2]); err != nil {
				return fmt.Errorf("failed to read DNS resp payload length: %w", err)
			}
			respLen := int(binary.BigEndian.Uint16(bReq))
			// Try to reuse the buf.
			var buf []byte
			if len(bReq) < respLen {
				buf = pool.Get(respLen)
				defer pool.Put(buf)
			} else {
				buf = bReq
			}
			var n int
			if n, err = io.ReadFull(conn, buf[:respLen]); err != nil {
				return fmt.Errorf("failed to read DNS resp payload: %w", err)
			}
			var msg dnsmessage.Msg
			if err = msg.Unpack(buf[:n]); err != nil {
				return err
			}
			respMsg = &msg
		} else if upstream.Scheme == "https" {

			httpTransport := http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return &netproxy.FakeNetConn{Conn: conn}, nil
				},
			}
			client := http.Client{
				Transport: &httpTransport,
			}
			msg, err := httpDNS(&client, dialArgument.bestTarget.String(), data)
			if err != nil {
				return err
			}
			respMsg = msg
		}
	default:
		return fmt.Errorf("unexpected l4proto: %v", dialArgument.l4proto)
	}

	// Close conn before the recursive call.
	conn.Close()
	connClosed = true

	// Route response.
	upstreamIndex, nextUpstream, err := c.routing.ResponseSelect(respMsg, upstream)
	if err != nil {
		return err
	}
	switch upstreamIndex {
	case consts.DnsResponseOutboundIndex_Accept:
		// Accept.
		if c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.WithFields(logrus.Fields{
				"question": respMsg.Question,
				"upstream": upstreamName,
			}).Traceln("Accept")
		}
	case consts.DnsResponseOutboundIndex_Reject:
		// Reject the request with empty answer.
		respMsg.Answer = nil
		if c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.WithFields(logrus.Fields{
				"question": respMsg.Question,
				"upstream": upstreamName,
			}).Traceln("Reject with empty answer")
		}
		// We also cache response reject.
	default:
		if c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.WithFields(logrus.Fields{
				"question":      respMsg.Question,
				"last_upstream": upstreamName,
				"next_upstream": nextUpstream.String(),
			}).Traceln("Change DNS upstream and resend")
		}
		return c.dialSend(invokingDepth+1, req, data, id, nextUpstream, needResp)
	}
	if upstreamIndex.IsReserved() && c.log.IsLevelEnabled(logrus.InfoLevel) {
		var (
			qname string
			qtype string
		)
		if len(respMsg.Question) > 0 {
			q := respMsg.Question[0]
			qname = strings.ToLower(q.Name)
			qtype = QtypeToString(q.Qtype)
		}
		fields := logrus.Fields{
			"network":  networkType.String(),
			"outbound": dialArgument.bestOutbound.Name,
			"policy":   dialArgument.bestOutbound.GetSelectionPolicy(),
			"dialer":   dialArgument.bestDialer.Property().Name,
			"_qname":   qname,
			"qtype":    qtype,
			"pid":      req.routingResult.Pid,
			"dscp":     req.routingResult.Dscp,
			"pname":    ProcessName2String(req.routingResult.Pname[:]),
			"mac":      Mac2String(req.routingResult.Mac[:]),
		}
		switch upstreamIndex {
		case consts.DnsResponseOutboundIndex_Accept:
			c.log.WithFields(fields).Infof("%v <-> %v", RefineSourceToShow(req.realSrc, req.realDst.Addr()), RefineAddrPortToShow(dialArgument.bestTarget))
		case consts.DnsResponseOutboundIndex_Reject:
			c.log.WithFields(fields).Infof("%v -> reject", RefineSourceToShow(req.realSrc, req.realDst.Addr()))
		default:
			return fmt.Errorf("unknown upstream: %v", upstreamIndex.String())
		}
	}
	if err = c.NormalizeAndCacheDnsResp_(respMsg); err != nil {
		return err
	}
	if needResp {
		// Keep the id the same with request.
		respMsg.Id = id
		respMsg.Compress = true
		data, err = respMsg.Pack()
		if err != nil {
			return err
		}
		if err = sendPkt(c.log, data, req.realDst, req.realSrc, req.src, req.lConn); err != nil {
			return err
		}
	}
	return nil
}

func httpDNS(client *http.Client, target string, data []byte) (respMsg *dnsmessage.Msg, err error) {
	serverURL := url.URL{
		Scheme: "https",
		Host:   target,
		Path:   "/dns-query",
	}

	req, err := http.NewRequest(http.MethodPost, serverURL.String(), strings.NewReader(string(data)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var msg dnsmessage.Msg
	if err = msg.Unpack(buf); err != nil {
		return nil, err
	}
	respMsg = &msg
	return respMsg, nil
}
