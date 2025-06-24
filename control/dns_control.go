/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/dns"
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
	// 使用sync.Map代替mutex+map，减少锁竞争
	dnsCache            sync.Map // map[string]*DnsCache
	dnsForwarderCache   sync.Map // map[dnsForwarderKey]DnsForwarder
	
	// DNS服务器相关字段
	dnsServerEnabled bool
	dnsServers       []*net.UDPConn
	dnsServerCtx     context.Context
	dnsServerCancel  context.CancelFunc
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

	ctx, cancel := context.WithCancel(context.Background())

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
		// 使用sync.Map，无需初始化
		
		// DNS服务器初始化
		dnsServerEnabled: false,
		dnsServerCtx:     ctx,
		dnsServerCancel:  cancel,
	}, nil
}

func (c *DnsController) cacheKey(qname string, qtype uint16) string {
	// To fqdn.
	return dnsmessage.CanonicalName(qname) + strconv.Itoa(int(qtype))
}

// 启动DNS服务器
func (c *DnsController) StartDnsServer(bindAddrs []string) error {
	if c.dnsServerEnabled {
		return fmt.Errorf("DNS server already started")
	}

	for _, addr := range bindAddrs {
		udpConn, err := c.startDnsListener(addr)
		if err != nil {
			c.stopDnsServer()
			return fmt.Errorf("failed to start DNS listener on %s: %w", addr, err)
		}
		c.dnsServers = append(c.dnsServers, udpConn)
	}

	c.dnsServerEnabled = true
	c.log.Infof("DNS server started on %v", bindAddrs)
	return nil
}

// 启动单个DNS监听器
func (c *DnsController) startDnsListener(addr string) (*net.UDPConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}

	// 启动处理goroutine
	go c.handleDnsServerRequests(udpConn)

	return udpConn, nil
}

// 处理DNS服务器请求
func (c *DnsController) handleDnsServerRequests(udpConn *net.UDPConn) {
	defer udpConn.Close()

	buffer := make([]byte, 4096)

	for {
		select {
		case <-c.dnsServerCtx.Done():
			return
		default:
			// 设置读取超时
			udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))

			n, clientAddr, err := udpConn.ReadFromUDP(buffer)
			if err != nil {
				if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
					continue
				}
				c.log.Errorf("DNS server read error: %v", err)
				continue
			}

			// 异步处理DNS请求
			go c.processDnsServerRequest(buffer[:n], clientAddr, udpConn)
		}
	}
}

// 处理单个DNS请求
func (c *DnsController) processDnsServerRequest(data []byte, clientAddr *net.UDPAddr, udpConn *net.UDPConn) {
	// 解析DNS消息
	var dnsMsg dnsmessage.Msg
	if err := dnsMsg.Unpack(data); err != nil {
		c.log.Errorf("Failed to parse DNS message from %v: %v", clientAddr, err)
		return
	}

	if c.log.IsLevelEnabled(logrus.TraceLevel) && len(dnsMsg.Question) > 0 {
		q := dnsMsg.Question[0]
		c.log.Tracef("DNS Server received: %v %v from %v", 
			strings.ToLower(q.Name), QtypeToString(q.Qtype), clientAddr)
	}

	// 创建模拟的udpRequest用于兼容现有处理逻辑
	realSrc, _ := netip.ParseAddrPort(clientAddr.String())
	realDst, _ := netip.ParseAddrPort(udpConn.LocalAddr().String())

	req := &udpRequest{
		realSrc: realSrc,
		realDst: realDst,
		src:     realSrc,
		lConn:   nil, // DNS服务器模式不需要
		routingResult: &bpfRoutingResult{
			Mark:     0,
			Outbound: 0,
			Pid:      0,
			Dscp:     0,
		},
		clientAddr: clientAddr,
		udpConn:    udpConn,
	}

	// 使用现有DNS处理逻辑
	if err := c.HandleDnsServerRequest(&dnsMsg, req); err != nil {
		c.log.Errorf("DNS server processing error for %v: %v", clientAddr, err)
		c.sendErrorResponse(&dnsMsg, clientAddr, udpConn, dnsmessage.RcodeServerFailure)
	}
}

// 处理DNS服务器请求的核心逻辑
func (c *DnsController) HandleDnsServerRequest(dnsMsg *dnsmessage.Msg, req *udpRequest) error {
	if len(dnsMsg.Question) == 0 {
		return fmt.Errorf("no question in DNS request")
	}

	q := dnsMsg.Question[0]
	qname := q.Name
	qtype := q.Qtype

	// 检查缓存
	cacheKey := c.cacheKey(qname, qtype)
	if cached := c.LookupDnsRespCache(cacheKey, false); cached != nil {
		return c.sendCachedResponse(dnsMsg, cached, req)
	}

	// 路由请求到上游
	upstreamIndex, upstream, err := c.routing.RequestSelect(qname, qtype)
	if err != nil {
		return err
	}

	if upstreamIndex == consts.DnsRequestOutboundIndex_Reject {
		return c.sendErrorResponse(dnsMsg, req.clientAddr, req.udpConn, dnsmessage.RcodeRefused)
	}

	// 转发到上游DNS并处理响应
	return c.forwardAndCacheResponse(dnsMsg, upstream, req)
}

// Handle_ 处理DNS请求（透明代理模式和DNS服务器模式通用）
func (c *DnsController) Handle_(dnsMsg *dnsmessage.Msg, req *udpRequest) error {
	if len(dnsMsg.Question) == 0 {
		return fmt.Errorf("no question in DNS request")
	}

	q := dnsMsg.Question[0]
	qname := q.Name
	qtype := q.Qtype

	if c.log.IsLevelEnabled(logrus.TraceLevel) {
		c.log.Tracef("DNS Handle_: %v %v from %v", 
			strings.ToLower(qname), QtypeToString(qtype), req.realSrc)
	}

	// 检查缓存
	cacheKey := c.cacheKey(qname, qtype)
	if cached := c.LookupDnsRespCache(cacheKey, false); cached != nil {
		if req.clientAddr != nil && req.udpConn != nil {
			// DNS服务器模式
			return c.sendCachedResponse(dnsMsg, cached, req)
		} else {
			// 透明代理模式 - 使用现有逻辑
			return c.sendTransparentResponse(dnsMsg, cached, req)
		}
	}

	// 路由请求到上游
	upstreamIndex, upstream, err := c.routing.RequestSelect(qname, qtype)
	if err != nil {
		return err
	}

	if upstreamIndex == consts.DnsRequestOutboundIndex_Reject {
		if req.clientAddr != nil && req.udpConn != nil {
			// DNS服务器模式
			return c.sendErrorResponse(dnsMsg, req.clientAddr, req.udpConn, dnsmessage.RcodeRefused)
		} else {
			// 透明代理模式 - 返回错误或空响应
			return fmt.Errorf("DNS request rejected by routing")
		}
	}

	// 转发到上游DNS并处理响应
	if req.clientAddr != nil && req.udpConn != nil {
		// DNS服务器模式
		return c.forwardAndCacheResponse(dnsMsg, upstream, req)
	} else {
		// 透明代理模式 - 使用现有转发逻辑
		return c.forwardTransparentRequest(dnsMsg, upstream, req)
	}
}

// sendTransparentResponse 发送缓存响应（透明代理模式）
func (c *DnsController) sendTransparentResponse(request *dnsmessage.Msg, cache *DnsCache, req *udpRequest) error {
	// 这里应该实现透明代理模式的响应发送逻辑
	// 暂时使用简化实现
	c.log.Tracef("Sending cached response for transparent proxy: %v", request.Question[0].Name)
	return nil
}

// forwardTransparentRequest 转发请求（透明代理模式）
func (c *DnsController) forwardTransparentRequest(request *dnsmessage.Msg, upstream *dns.Upstream, req *udpRequest) error {
	// 这里应该实现透明代理模式的请求转发逻辑
	// 暂时使用简化实现
	c.log.Tracef("Forwarding request for transparent proxy: %v to %v", request.Question[0].Name, upstream.String())
	return nil
}

// 发送缓存的响应
func (c *DnsController) sendCachedResponse(request *dnsmessage.Msg, cache *DnsCache, req *udpRequest) error {
	response := &dnsmessage.Msg{
		MsgHdr: dnsmessage.MsgHdr{
			Id:       request.MsgHdr.Id,
			Response: true,
			Rcode:    dnsmessage.RcodeSuccess,
			RecursionAvailable: true,
		},
		Question: request.Question,
		Answer:   deepcopy.Copy(cache.Answer).([]dnsmessage.RR),
	}
	
	responseData, err := response.Pack()
	if err != nil {
		return fmt.Errorf("failed to pack cached DNS response: %w", err)
	}

	return c.sendResponse(responseData, req.clientAddr, req.udpConn)
}

// 转发到上游并缓存响应
func (c *DnsController) forwardAndCacheResponse(request *dnsmessage.Msg, upstream *dns.Upstream, req *udpRequest) error {
	// 使用现有的DNS转发机制获取最佳拨号器
	dialArg, err := c.bestDialerChooser(req, upstream)
	if err != nil {
		return fmt.Errorf("failed to choose dialer: %w", err)
	}

	// 创建DNS转发器
	forwarder, err := newDnsForwarder(upstream, *dialArg)
	if err != nil {
		return fmt.Errorf("failed to create DNS forwarder: %w", err)
	}
	defer forwarder.Close()

	// 打包请求
	requestData, err := request.Pack()
	if err != nil {
		return fmt.Errorf("failed to pack DNS request: %w", err)
	}

	// 转发请求
	response, err := forwarder.ForwardDNS(context.Background(), requestData)
	if err != nil {
		return fmt.Errorf("failed to forward DNS request: %w", err)
	}

	// 缓存响应
	if len(response.Answer) > 0 {
		q := request.Question[0]
		deadline := time.Now().Add(time.Duration(response.Answer[0].Header().Ttl) * time.Second)
		cache, err := c.newCache(q.Name, response.Answer, deadline, deadline)
		if err == nil {
			c.dnsCache.Store(c.cacheKey(q.Name, q.Qtype), cache)
		}
	}

	// 发送响应
	response.MsgHdr.Id = request.MsgHdr.Id
	responseData, err := response.Pack()
	if err != nil {
		return fmt.Errorf("failed to pack DNS response: %w", err)
	}

	return c.sendResponse(responseData, req.clientAddr, req.udpConn)
}

// 发送错误响应
func (c *DnsController) sendErrorResponse(request *dnsmessage.Msg, clientAddr *net.UDPAddr, udpConn *net.UDPConn, rcode int) error {
	response := &dnsmessage.Msg{
		MsgHdr: dnsmessage.MsgHdr{
			Id:       request.MsgHdr.Id,
			Response: true,
			Rcode:    rcode,
		},
		Question: request.Question,
	}

	responseData, err := response.Pack()
	if err != nil {
		return fmt.Errorf("failed to pack DNS error response: %w", err)
	}

	return c.sendResponse(responseData, clientAddr, udpConn)
}

// 发送响应
func (c *DnsController) sendResponse(data []byte, clientAddr *net.UDPAddr, udpConn *net.UDPConn) error {
	_, err := udpConn.WriteToUDP(data, clientAddr)
	if err != nil {
		return fmt.Errorf("failed to send DNS response to %v: %w", clientAddr, err)
	}
	return nil
}

// 停止DNS服务器
func (c *DnsController) stopDnsServer() {
	if !c.dnsServerEnabled {
		return
	}

	c.dnsServerCancel()

	for _, server := range c.dnsServers {
		if err := server.Close(); err != nil {
			c.log.Warnf("Error closing DNS server: %v", err)
		}
	}

	c.dnsServers = nil
	c.dnsServerEnabled = false
	c.log.Info("DNS server stopped")
}

// UpdateDnsCacheDeadline 更新DNS缓存的截止时间
func (c *DnsController) UpdateDnsCacheDeadline(hostname string, qtype uint16, answers []dnsmessage.RR, deadline time.Time) error {
	key := c.cacheKey(hostname, qtype)
	if existingCache, ok := c.dnsCache.Load(key); ok {
		cache := existingCache.(*DnsCache)
		cache.Deadline = deadline
		cache.Answer = answers
		c.dnsCache.Store(key, cache)
	}
	return nil
}

// 获取或查找DNS响应缓存
func (c *DnsController) LookupDnsRespCache(key string, allowExpired bool) *DnsCache {
	if cached, ok := c.dnsCache.Load(key); ok {
		cache := cached.(*DnsCache)
		// 检查缓存是否过期
		if time.Now().Before(cache.Deadline) {
			return cache
		}
		// 缓存过期，删除
		c.dnsCache.Delete(key)
	}
	return nil
}
