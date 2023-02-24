/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2023, v2rayA Organization <team@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"hash/fnv"
	"math/rand"
	"net/netip"
	"strings"
)

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
	var strBody string
	switch body := w.Rsc.Body.(type) {
	case *dnsmessage.AResource:
		strBody = netip.AddrFrom4(body.A).String()
	case *dnsmessage.AAAAResource:
		strBody = netip.AddrFrom16(body.AAAA).String()
	default:
		strBody = body.GoString()
	}
	return fmt.Sprintf("%v(%v): %v", w.Rsc.Header.Name.String(), w.Rsc.Header.Type.String(), strBody)
}
func FormatDnsRsc(ans []dnsmessage.Resource) string {
	var w []string
	for _, a := range ans {
		w = append(w, RscWrapper{Rsc: a}.String())
	}
	return strings.Join(w, "; ")
}
