/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2023, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/mzz2017/softwind/netproxy"
	"github.com/mzz2017/softwind/pool"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	MaxDnsLookupDepth      = 3
	minFirefoxCacheTimeout = 120 * time.Second
)

var (
	SuspectedRushAnswerError     = fmt.Errorf("suspected DNS rush-answer")
	UnsupportedQuestionTypeError = fmt.Errorf("unsupported question type")
)

type DnsControllerOption struct {
	Log                 *logrus.Logger
	CacheAccessCallback func(cache *DnsCache) (err error)
	NewCache            func(fqdn string, answers []dnsmessage.Resource, deadline time.Time) (cache *DnsCache, err error)
	BestDialerChooser   func(req *udpRequest, upstream *dns.Upstream) (*dialArgument, error)
}

type DnsController struct {
	routing *dns.Dns

	log                 *logrus.Logger
	cacheAccessCallback func(cache *DnsCache) (err error)
	newCache            func(fqdn string, answers []dnsmessage.Resource, deadline time.Time) (cache *DnsCache, err error)
	bestDialerChooser   func(req *udpRequest, upstream *dns.Upstream) (*dialArgument, error)

	// mutex protects the dnsCache.
	dnsCacheMu sync.Mutex
	dnsCache   map[string]*DnsCache
}

func NewDnsController(routing *dns.Dns, option *DnsControllerOption) (c *DnsController, err error) {
	return &DnsController{
		routing: routing,

		log:                 option.Log,
		cacheAccessCallback: option.CacheAccessCallback,
		newCache:            option.NewCache,
		bestDialerChooser:   option.BestDialerChooser,

		dnsCacheMu: sync.Mutex{},
		dnsCache:   make(map[string]*DnsCache),
	}, nil
}

func (c *DnsController) LookupDnsRespCache(domain string, t dnsmessage.Type) (cache *DnsCache) {
	now := time.Now()

	// To fqdn.
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}
	c.dnsCacheMu.Lock()
	cache, ok := c.dnsCache[strings.ToLower(domain)+t.String()]
	c.dnsCacheMu.Unlock()
	// We should make sure the remaining TTL is greater than 120s (minFirefoxCacheTimeout), or
	// return nil and request a new lookup to refresh the cache.
	if ok && cache.Deadline.After(now.Add(minFirefoxCacheTimeout)) {
		return cache
	}
	return nil
}

// LookupDnsRespCache_ will modify the msg in place.
func (c *DnsController) LookupDnsRespCache_(msg *dnsmessage.Message) (resp []byte) {
	if len(msg.Questions) == 0 {
		return nil
	}
	q := msg.Questions[0]
	if msg.Response {
		return nil
	}
	switch q.Type {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
	default:
		return nil
	}
	cache := c.LookupDnsRespCache(q.Name.String(), q.Type)
	if cache != nil {
		cache.FillInto(msg)
		b, err := msg.Pack()
		if err != nil {
			c.log.Warnf("failed to pack: %v", err)
			return nil
		}
		if err = c.cacheAccessCallback(cache); err != nil {
			c.log.Warnf("failed to BatchUpdateDomainRouting: %v", err)
			return nil
		}
		return b
	}
	return nil
}

// DnsRespHandler handle DNS resp.
func (c *DnsController) DnsRespHandler(data []byte, validateRushAns bool) (newMsg *dnsmessage.Message, err error) {
	var msg dnsmessage.Message
	if err = msg.Unpack(data); err != nil {
		return nil, fmt.Errorf("unpack dns pkt: %w", err)
	}
	// Check healthy resp.
	if !msg.Response || len(msg.Questions) == 0 {
		return &msg, nil
	}

	q := msg.Questions[0]

	// Check suc resp.
	if msg.RCode != dnsmessage.RCodeSuccess {
		return &msg, nil
	}

	// Check req type.
	switch q.Type {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
	default:
		return &msg, nil
	}

	// Set ttl.
	var ttl uint32
	for i := range msg.Answers {
		if ttl == 0 {
			ttl = msg.Answers[i].Header.TTL
		}
		// Set TTL = zero. This requests applications must resend every request.
		// However, it may be not defined in the standard.
		msg.Answers[i].Header.TTL = 0
	}

	// Check if there is any A/AAAA record.
	var hasIpRecord bool
loop:
	for i := range msg.Answers {
		switch msg.Answers[i].Header.Type {
		case dnsmessage.TypeA, dnsmessage.TypeAAAA:
			hasIpRecord = true
			break loop
		}
	}
	if !hasIpRecord {
		return &msg, nil
	}

	if validateRushAns {
		exist, e := EnsureAdditionalOpt(&msg, false)
		if e != nil && !errors.Is(e, UnsupportedQuestionTypeError) {
			c.log.Warnf("EnsureAdditionalOpt: %v", e)
		}
		if e == nil && !exist {
			// Additional record OPT in the request was ensured, and in normal case the resp should also set it.
			// This DNS packet may be a rush-answer, and we should reject it.
			c.log.WithFields(logrus.Fields{
				"ques":     q,
				"addition": FormatDnsRsc(msg.Additionals),
				"ans":      FormatDnsRsc(msg.Answers),
			}).Traceln("DNS rush-answer detected")
			return nil, SuspectedRushAnswerError
		}
	}

	// Update DnsCache.
	if c.log.IsLevelEnabled(logrus.TraceLevel) {
		c.log.WithFields(logrus.Fields{
			"qname":    q.Name,
			"rcode":    msg.RCode,
			"ans":      FormatDnsRsc(msg.Answers),
			"auth":     FormatDnsRsc(msg.Authorities),
			"addition": FormatDnsRsc(msg.Additionals),
		}).Tracef("Update DNS record cache")
	}
	cacheTimeout := time.Duration(ttl) * time.Second // TTL.
	if cacheTimeout < minFirefoxCacheTimeout {
		cacheTimeout = minFirefoxCacheTimeout
	}
	cacheTimeout += 5 * time.Second // DNS lookup timeout.

	if err = c.UpdateDnsCache(q.Name.String(), q.Type.String(), msg.Answers, time.Now().Add(cacheTimeout)); err != nil {
		return nil, err
	}
	// Pack to get newData.
	return &msg, nil
}

func (c *DnsController) UpdateDnsCache(host string, dnsTyp string, answers []dnsmessage.Resource, deadline time.Time) (err error) {
	var fqdn string
	if strings.HasSuffix(host, ".") {
		fqdn = host
		host = host[:len(host)-1]
	} else {
		fqdn = host + "."
	}
	// Bypass pure IP.
	if _, err = netip.ParseAddr(host); err == nil {
		return nil
	}
	cacheKey := fqdn + dnsTyp
	c.dnsCacheMu.Lock()
	cache, ok := c.dnsCache[cacheKey]
	if ok {
		c.dnsCacheMu.Unlock()
		cache.Deadline = deadline
		cache.Answers = answers
	} else {
		cache, err = c.newCache(fqdn, answers, deadline)
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

func (c *DnsController) DnsRespHandlerFactory(validateRushAnsFunc func(from netip.AddrPort) bool) func(data []byte, from netip.AddrPort) (msg *dnsmessage.Message, err error) {
	return func(data []byte, from netip.AddrPort) (msg *dnsmessage.Message, err error) {
		// Do not return conn-unrelated err in this func.

		validateRushAns := validateRushAnsFunc(from)
		msg, err = c.DnsRespHandler(data, validateRushAns)
		if err != nil {
			if errors.Is(err, SuspectedRushAnswerError) {
				if validateRushAns {
					// Reject DNS rush-answer.
					c.log.WithFields(logrus.Fields{
						"from": from,
					}).Tracef("DNS rush-answer rejected")
					return nil, nil
				}
			} else {
				if c.log.IsLevelEnabled(logrus.DebugLevel) {
					c.log.Debugf("DnsRespHandler: %v", err)
				}
				return nil, err
			}
		}
		return msg, nil
	}
}

type udpRequest struct {
	lanWanFlag    consts.LanWanFlag
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
}

func (c *DnsController) Handle_(dnsMessage *dnsmessage.Message, req *udpRequest) (err error) {
	if resp := c.LookupDnsRespCache_(dnsMessage); resp != nil {
		// Send cache to client directly.
		if err = sendPkt(resp, req.realDst, req.realSrc, req.src, req.lConn, req.lanWanFlag); err != nil {
			return fmt.Errorf("failed to write cached DNS resp: %w", err)
		}
		if c.log.IsLevelEnabled(logrus.DebugLevel) && len(dnsMessage.Questions) > 0 {
			q := dnsMessage.Questions[0]
			c.log.Tracef("UDP(DNS) %v <-> Cache: %v %v",
				RefineSourceToShow(req.realSrc, req.realDst.Addr(), req.lanWanFlag), strings.ToLower(q.Name.String()), q.Type,
			)
		}
		return nil
	}

	// Make sure there is additional record OPT in the request to filter DNS rush-answer in the response process.
	// Because rush-answer has no resp OPT. We can distinguish them from multiple responses.
	// Note that additional record OPT may not be supported by home router either.
	_, _ = EnsureAdditionalOpt(dnsMessage, true)

	// Route request.
	upstream, err := c.routing.RequestSelect(dnsMessage)
	if err != nil {
		return err
	}

	if c.log.IsLevelEnabled(logrus.TraceLevel) {
		upstreamName := "asis"
		if upstream != nil {
			upstreamName = upstream.String()
		}
		c.log.WithFields(logrus.Fields{
			"question": dnsMessage.Questions,
			"upstream": upstreamName,
		}).Traceln("Request to DNS upstream")
	}

	// Re-pack DNS packet.
	data, err := dnsMessage.Pack()
	if err != nil {
		return fmt.Errorf("pack DNS packet: %w", err)
	}
	return c.dialSend(req, data, dnsMessage.ID, upstream, 0)
}

func (c *DnsController) dialSend(req *udpRequest, data []byte, id uint16, upstream *dns.Upstream, invokingDepth int) (err error) {
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
		IsDns:     true, // UDP relies on DNS check result.
	}

	// dnsRespHandler caches dns response and check rush answers.
	dnsRespHandler := c.DnsRespHandlerFactory(func(from netip.AddrPort) bool {
		// We only validate rush-ans when outbound is direct and pkt does not send to a home device.
		// Because additional record OPT may not be supported by home router.
		// So se should trust home devices even if they make rush-answer (or looks like).
		return dialArgument.bestDialer.Property().Name == "direct" &&
			!from.Addr().IsPrivate() &&
			!from.Addr().IsLoopback() &&
			!from.Addr().IsUnspecified()
	})
	// Dial and send.
	var respMsg *dnsmessage.Message
	// defer in a recursive call will delay Close(), thus we Close() before
	// the next recursive call. However, a connection cannot be closed twice.
	// We should set a connClosed flag to avoid it.
	var connClosed bool
	var conn netproxy.Conn
	// TODO: Rewritten domain should not use full-cone (such as VMess Packet Addr).
	// 		Maybe we should set up a mapping for UDP: Dialer + Target Domain => Remote Resolved IP.
	//		However, games may not use QUIC for communication, thus we cannot use domain to dial, which is fine.
	switch dialArgument.l4proto {
	case consts.L4ProtoStr_UDP:
		// Get udp endpoint.

		// TODO: connection pool.
		conn, err = dialArgument.bestDialer.Dial(
			MagicNetwork("udp", dialArgument.mark),
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

		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		dnsReqCtx, cancelDnsReqCtx := context.WithTimeout(context.TODO(), 5*time.Second)
		defer cancelDnsReqCtx()
		go func() {
			// Send DNS request at 0, 2, 4 seconds.
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
				case <-time.After(2 * time.Second):
				}
			}
		}()

		// We can block here because we are in a coroutine.
		respBuf := pool.Get(512)
		defer pool.Put(respBuf)
		for {
			// Wait for response.
			n, err := conn.Read(respBuf)
			if err != nil {
				return fmt.Errorf("failed to read from: %v (dialer: %v): %w", dialArgument.bestTarget, dialArgument.bestDialer.Property().Name, err)
			}
			cancelDnsReqCtx()
			respMsg, err = dnsRespHandler(respBuf[:n], dialArgument.bestTarget)
			if err != nil {
				return err
			}
			if respMsg != nil {
				break
			}
		}
	case consts.L4ProtoStr_TCP:
		// We can block here because we are in a coroutine.

		conn, err = dialArgument.bestDialer.Dial(MagicNetwork("tcp", dialArgument.mark), dialArgument.bestTarget.String())
		if err != nil {
			return fmt.Errorf("failed to dial proxy to tcp: %w", err)
		}
		defer func() {
			if !connClosed {
				conn.Close()
			}
		}()

		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
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
		respMsg, err = dnsRespHandler(buf[:n], dialArgument.bestTarget)
		if respMsg == nil && err == nil {
			err = fmt.Errorf("bad DNS response")
		}
		if err != nil {
			return fmt.Errorf("failed to write DNS resp to client: %w", err)
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
				"question": respMsg.Questions,
				"upstream": upstreamName,
			}).Traceln("Accept")
		}
	case consts.DnsResponseOutboundIndex_Reject:
		// Reject the request with empty answer.
		respMsg.Answers = nil
		if c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.WithFields(logrus.Fields{
				"question": respMsg.Questions,
				"upstream": upstreamName,
			}).Traceln("Reject with empty answer")
		}
	default:
		if c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.WithFields(logrus.Fields{
				"question":      respMsg.Questions,
				"last_upstream": upstreamName,
				"next_upstream": nextUpstream.String(),
			}).Traceln("Change DNS upstream and resend")
		}
		return c.dialSend(req, data, id, nextUpstream, invokingDepth+1)
	}
	if upstreamIndex.IsReserved() && c.log.IsLevelEnabled(logrus.InfoLevel) {
		var qname, qtype string
		if len(respMsg.Questions) > 0 {
			q := respMsg.Questions[0]
			qname = strings.ToLower(q.Name.String())
			qtype = q.Type.String()
		}
		fields := logrus.Fields{
			"network":  networkType.String(),
			"outbound": dialArgument.bestOutbound.Name,
			"policy":   dialArgument.bestOutbound.GetSelectionPolicy(),
			"dialer":   dialArgument.bestDialer.Property().Name,
			"qname":    qname,
			"qtype":    qtype,
			"pid":      req.routingResult.Pid,
			"pname":    ProcessName2String(req.routingResult.Pname[:]),
			"mac":      Mac2String(req.routingResult.Mac[:]),
		}
		switch upstreamIndex {
		case consts.DnsResponseOutboundIndex_Accept:
			c.log.WithFields(fields).Infof("%v <-> %v", RefineSourceToShow(req.realSrc, req.realDst.Addr(), req.lanWanFlag), RefineAddrPortToShow(dialArgument.bestTarget))
		case consts.DnsResponseOutboundIndex_Reject:
			c.log.WithFields(fields).Infof("%v -> reject", RefineSourceToShow(req.realSrc, req.realDst.Addr(), req.lanWanFlag))
		default:
			return fmt.Errorf("unknown upstream: %v", upstreamIndex.String())
		}
	}
	// Keep the id the same with request.
	respMsg.ID = id
	data, err = respMsg.Pack()
	if err != nil {
		return err
	}
	if err = sendPkt(data, req.realDst, req.realSrc, req.src, req.lConn, req.lanWanFlag); err != nil {
		return err
	}
	return nil
}
