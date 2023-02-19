/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, v2rayA Organization <team@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/mohae/deepcopy"
	"github.com/sirupsen/logrus"
	"github.com/v2rayA/dae/common"
	"golang.org/x/net/dns/dnsmessage"
	"hash/fnv"
	"math/rand"
	"net/netip"
	"strings"
	"time"
)

var (
	SuspectedRushAnswerError     = fmt.Errorf("suspected DNS rush-answer")
	UnsupportedQuestionTypeError = fmt.Errorf("unsupported question type")
)

type dnsCache struct {
	DomainBitmap []uint32
	Answers      []dnsmessage.Resource
	Deadline     time.Time
}

func (c *dnsCache) FillInto(req *dnsmessage.Message) {
	req.Answers = deepcopy.Copy(c.Answers).([]dnsmessage.Resource)
	// Align question and answer Name.
	if len(req.Questions) > 0 {
		q := req.Questions[0]
		for i := range req.Answers {
			if strings.EqualFold(req.Answers[i].Header.Name.String(), q.Name.String()) {
				req.Answers[i].Header.Name.Data = q.Name.Data
			}
		}
	}
	req.RCode = dnsmessage.RCodeSuccess
	req.Response = true
	req.RecursionAvailable = true
	req.Truncated = false
}

func (c *dnsCache) IncludeIp(ip netip.Addr) bool {
	ip = common.ConvergeIp(ip)
	for _, ans := range c.Answers {
		switch body := ans.Body.(type) {
		case *dnsmessage.AResource:
			if !ip.Is4() {
				continue
			}
			if netip.AddrFrom4(body.A) == ip {
				return true
			}
		case *dnsmessage.AAAAResource:
			if !ip.Is6() {
				continue
			}
			if netip.AddrFrom16(body.AAAA) == ip {
				return true
			}
		}
	}
	return false
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
	// Construct keys and vals, and BpfMapBatchUpdate.
	var keys [][4]uint32
	var vals []bpfDomainRouting
	for _, ip := range ips {
		ip6 := ip.As16()
		keys = append(keys, common.Ipv6ByteSliceToUint32Array(ip6[:]))
		vals = append(vals, bpfDomainRouting{
			Bitmap: [3]uint32{},
		})
		if len(cache.DomainBitmap) != len(vals[len(vals)-1].Bitmap) {
			return fmt.Errorf("domain bitmap length not sync with kern program")
		}
		copy(vals[len(vals)-1].Bitmap[:], cache.DomainBitmap)
	}
	if _, err := BpfMapBatchUpdate(c.core.bpf.DomainRoutingMap, keys, vals, &ebpf.BatchOptions{
		ElemFlags: uint64(ebpf.UpdateAny),
	}); err != nil {
		return err
	}
	return nil
}

func (c *ControlPlane) lookupDnsRespCache(domain string, t dnsmessage.Type) (cache *dnsCache) {
	now := time.Now()

	// To fqdn.
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}
	c.dnsCacheMu.Lock()
	cache, ok := c.dnsCache[strings.ToLower(domain)+t.String()]
	c.dnsCacheMu.Unlock()
	if ok && cache.Deadline.After(now) {
		return cache
	}
	return nil
}

func (c *ControlPlane) LookupDnsRespCache_(msg *dnsmessage.Message) (resp []byte) {
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
	cache := c.lookupDnsRespCache(q.Name.String(), q.Type)
	if cache != nil {
		cache.FillInto(msg)
		b, err := msg.Pack()
		if err != nil {
			c.log.Warnf("failed to pack: %v", err)
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

// FlipDnsQuestionCase is used to reduce dns pollution.
func FlipDnsQuestionCase(dm *dnsmessage.Message) {
	if len(dm.Questions) == 0 {
		return
	}
	q := &dm.Questions[0]
	// For reproducibility, we use dm.ID as input and add some entropy to make the results more discrete.
	h := fnv.New64()
	var buf [4]byte
	binary.BigEndian.PutUint16(buf[:], dm.ID)
	h.Write(buf[:2])
	binary.BigEndian.PutUint32(buf[:], 20230204) // entropy
	h.Write(buf[:])
	r := rand.New(rand.NewSource(int64(h.Sum64())))
	perm := r.Perm(int(q.Name.Length))
	for i := 0; i < int(q.Name.Length/3); i++ {
		j := perm[i]
		// Upper to lower; lower to upper.
		if q.Name.Data[j] >= 'a' && q.Name.Data[j] <= 'z' {
			q.Name.Data[j] -= 'a' - 'A'
		} else if q.Name.Data[j] >= 'A' && q.Name.Data[j] <= 'Z' {
			q.Name.Data[j] += 'a' - 'A'
		}
	}
}

// EnsureAdditionalOpt makes sure there is additional record OPT in the request.
func EnsureAdditionalOpt(dm *dnsmessage.Message, isReqAdd bool) (bool, error) {
	// Check healthy resp.
	if isReqAdd == dm.Response || dm.RCode != dnsmessage.RCodeSuccess || len(dm.Questions) == 0 {
		return false, UnsupportedQuestionTypeError
	}
	q := dm.Questions[0]
	switch q.Type {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
	default:
		return false, UnsupportedQuestionTypeError
	}

	for _, ad := range dm.Additionals {
		if ad.Header.Type == dnsmessage.TypeOPT {
			// Already has additional record OPT.
			return true, nil
		}
	}
	if !isReqAdd {
		return false, nil
	}
	// Add one.
	dm.Additionals = append(dm.Additionals, dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName("."),
			Type:  dnsmessage.TypeOPT,
			Class: 512, TTL: 0, Length: 0,
		},
		Body: &dnsmessage.OPTResource{
			Options: nil,
		},
	})
	return false, nil
}

type RscWrapper struct {
	Rsc dnsmessage.Resource
}

func (w RscWrapper) String() string {
	return fmt.Sprintf("%v: %v", w.Rsc.Header.GoString(), w.Rsc.Body.GoString())
}
func FormatDnsRsc(ans []dnsmessage.Resource) (w []string) {
	for _, a := range ans {
		w = append(w, RscWrapper{Rsc: a}.String())
	}
	return w
}

// DnsRespHandler handle DNS resp. This function should be invoked when cache miss.
func (c *ControlPlane) DnsRespHandler(data []byte, validateRushAns bool) (newData []byte, err error) {
	var msg dnsmessage.Message
	if err = msg.Unpack(data); err != nil {
		return nil, fmt.Errorf("unpack dns pkt: %w", err)
	}
	// Check healthy resp.
	if !msg.Response || len(msg.Questions) == 0 {
		return data, nil
	}

	FlipDnsQuestionCase(&msg)
	q := msg.Questions[0]
	// Align Name.
	for i := range msg.Answers {
		if strings.EqualFold(msg.Answers[i].Header.Name.String(), q.Name.String()) {
			msg.Answers[i].Header.Name.Data = q.Name.Data
		}
	}
	for i := range msg.Additionals {
		if strings.EqualFold(msg.Additionals[i].Header.Name.String(), q.Name.String()) {
			msg.Additionals[i].Header.Name.Data = q.Name.Data
		}
	}
	for i := range msg.Authorities {
		if strings.EqualFold(msg.Authorities[i].Header.Name.String(), q.Name.String()) {
			msg.Authorities[i].Header.Name.Data = q.Name.Data
		}
	}

	// Check suc resp.
	if msg.RCode != dnsmessage.RCodeSuccess {
		return msg.Pack()
	}

	// Check req type.
	switch q.Type {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
	default:
		return msg.Pack()
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
		return msg.Pack()
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
				"ques": q,
				"addi": FormatDnsRsc(msg.Additionals),
				"ans":  FormatDnsRsc(msg.Answers),
			}).Traceln("DNS rush-answer detected")
			return nil, SuspectedRushAnswerError
		}
	}

	// Update dnsCache.
	c.log.WithFields(logrus.Fields{
		"qname": q.Name,
		"rcode": msg.RCode,
		"ans":   FormatDnsRsc(msg.Answers),
		"auth":  FormatDnsRsc(msg.Authorities),
		"addi":  FormatDnsRsc(msg.Additionals),
	}).Tracef("Update DNS record cache")
	if err = c.UpdateDnsCache(q.Name.String(), q.Type, msg.Answers, time.Now().Add(time.Duration(ttl)*time.Second+DnsNatTimeout)); err != nil {
		return nil, err
	}
	// Pack to get newData.
	return msg.Pack()
}

func (c *ControlPlane) UpdateDnsCache(host string, typ dnsmessage.Type, answers []dnsmessage.Resource, deadline time.Time) (err error) {
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
	cacheKey := fqdn + typ.String()
	c.dnsCacheMu.Lock()
	cache, ok := c.dnsCache[cacheKey]
	if ok {
		c.dnsCacheMu.Unlock()
		cache.Deadline = deadline
		cache.Answers = answers
	} else {
		cache = &dnsCache{
			DomainBitmap: c.routingMatcher.domainMatcher.MatchDomainBitmap(fqdn),
			Answers:      answers,
			Deadline:     deadline,
		}
		c.dnsCache[cacheKey] = cache
		c.dnsCacheMu.Unlock()
	}
	if err = c.BatchUpdateDomainRouting(cache); err != nil {
		return fmt.Errorf("BatchUpdateDomainRouting: %w", err)
	}
	return nil
}
