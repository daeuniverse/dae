/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, v2rayA Organization <team@v2raya.org>
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
	"github.com/v2rayA/dae/common/consts"
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
	DomainBitmap [consts.MaxMatchSetLen / 32]uint32
	Answers      []dnsmessage.Resource
	Deadline     time.Time
}

func (c *dnsCache) FillInto(req *dnsmessage.Message) {
	req.Answers = deepcopy.Copy(c.Answers).([]dnsmessage.Resource)
	// Align question and answer Name.
	if len(req.Questions) > 0 {
		q := req.Questions[0]
		if len(req.Answers) > 0 &&
			strings.EqualFold(req.Answers[0].Header.Name.String(), q.Name.String()) {
			req.Answers[0].Header.Name.Data = q.Name.Data
		}
	}
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
	if len(msg.Answers) > 0 &&
		strings.EqualFold(msg.Answers[0].Header.Name.String(), q.Name.String()) {
		msg.Answers[0].Header.Name.Data = q.Name.Data
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
	for i := range msg.Answers {
		switch msg.Answers[i].Header.Type {
		case dnsmessage.TypeA, dnsmessage.TypeAAAA:
			hasIpRecord = true
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
	c.mutex.Lock()
	fqdn := strings.ToLower(q.Name.String())
	cacheKey := fqdn + q.Type.String()
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
