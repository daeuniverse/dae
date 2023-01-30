/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, v2rayA Organization <team@v2raya.org>
 */

package control

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/v2rayA/dae/common"
	"github.com/v2rayA/dae/common/consts"
	"golang.org/x/net/dns/dnsmessage"
	"net/netip"
	"strings"
	"time"
)

type dnsCache struct {
	DomainBitmap [consts.MaxRoutingLen / 32]uint32
	Answers      []dnsmessage.Resource
	Deadline     time.Time
}

func (c *dnsCache) FillInto(req *dnsmessage.Message) {
	req.Answers = c.Answers
	req.RCode = dnsmessage.RCodeSuccess
	req.Response = true
	req.RecursionAvailable = true
	req.Truncated = false
}

// BatchUpdateDomainRouting update bpf map domain_routing. Since one IP may have multiple domains, this function should
// be invoked every A/AAAA-record lookup.
func (c *ControlPlane) BatchUpdateDomainRouting(cache *dnsCache) error {
	// Parse ips from DNS resp answers.
	var ips []netip.Addr
	for _, ans := range cache.Answers {
		switch ans.Header.Type {
		case dnsmessage.TypeA:
			ips = append(ips, netip.AddrFrom4(ans.Body.(*dnsmessage.AResource).A))
		case dnsmessage.TypeAAAA:
			ips = append(ips, netip.AddrFrom16(ans.Body.(*dnsmessage.AAAAResource).AAAA))
		}
	}

	// Update bpf map.
	// Construct keys and vals, and BatchUpdate.
	var keys [][4]uint32
	var vals []bpfDomainRouting
	for _, ip := range ips {
		ip6 := ip.As16()
		keys = append(keys, common.Ipv6ByteSliceToUint32Array(ip6[:]))
		vals = append(vals, bpfDomainRouting{
			Bitmap: cache.DomainBitmap,
		})
	}
	if _, err := BatchUpdate(c.bpf.DomainRoutingMap, keys, vals, &ebpf.BatchOptions{
		ElemFlags: uint64(ebpf.UpdateAny),
	}); err != nil {
		return err
	}
	return nil
}

func (c *ControlPlane) LookupDnsRespCache(msg *dnsmessage.Message) (resp []byte) {
	q := msg.Questions[0]
	if msg.Response {
		return nil
	}
	switch q.Type {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
	default:
		return nil
	}
	now := time.Now()
	c.mutex.Lock()
	cache, ok := c.dnsCache[strings.ToLower(q.Name.String())+q.Type.String()]
	c.mutex.Unlock()
	if ok && cache.Deadline.After(now) {
		//c.log.Debugln("DNS cache hit:", q.Name, q.Type)
		cache.FillInto(msg)
		b, err := msg.Pack()
		if err != nil {
			return nil
		}
		if err = c.BatchUpdateDomainRouting(cache); err != nil {
			c.log.Warnf("failed to BatchUpdateDomainRouting: %v", err)
			return nil
		}
		return b
	}
	return nil
}

// DnsRespHandler handle DNS resp. This function should be invoked when cache miss.
func (c *ControlPlane) DnsRespHandler(data []byte) (newData []byte, err error) {
	var msg dnsmessage.Message
	if err = msg.Unpack(data); err != nil {
		return nil, fmt.Errorf("unpack dns pkt: %w", err)
	}

	// Check healthy.
	if !msg.Response || msg.RCode != dnsmessage.RCodeSuccess {
		return data, nil
	}
	// Check req type.
	q := msg.Questions[0]
	switch q.Type {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
	default:
		return data, nil
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
	for i := range msg.Answers {
		switch msg.Answers[i].Header.Type {
		case dnsmessage.TypeA, dnsmessage.TypeAAAA:
			hasIpRecord = true
		}
	}
	if !hasIpRecord {
		return msg.Pack()
	}

	// Update dnsCache.
	c.mutex.Lock()
	fqdn := q.Name.String()
	cacheKey := strings.ToLower(fqdn) + q.Type.String()
	cache, ok := c.dnsCache[cacheKey]
	if ok {
		c.mutex.Unlock()
		cache.Deadline = time.Now().Add(time.Duration(ttl)*time.Second + DnsNatTimeout)
		cache.Answers = msg.Answers
	} else {
		cache = &dnsCache{
			DomainBitmap: c.MatchDomainBitmap(strings.TrimSuffix(fqdn, ".")),
			Answers:      msg.Answers,
			Deadline:     time.Now().Add(time.Duration(ttl)*time.Second + DnsNatTimeout),
		}
		c.dnsCache[cacheKey] = cache
		c.mutex.Unlock()
	}
	if err = c.BatchUpdateDomainRouting(cache); err != nil {
		return nil, fmt.Errorf("BatchUpdateDomainRouting: %w", err)
	}

	// Pack to get newData.
	return msg.Pack()
}
