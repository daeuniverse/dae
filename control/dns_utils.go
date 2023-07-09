/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2023, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"strings"

	dnsmessage "github.com/miekg/dns"
)

type RscWrapper struct {
	Rsc dnsmessage.RR
}

func (w RscWrapper) String() string {
	var strBody string
	switch body := w.Rsc.(type) {
	case *dnsmessage.A:
		strBody = body.A.String()
	case *dnsmessage.AAAA:
		strBody = body.AAAA.String()
	default:
		strBody = body.String()
	}
	return fmt.Sprintf("%v(%v): %v", w.Rsc.Header().Name, w.Rsc.Header().Rrtype, strBody)
}
func FormatDnsRsc(ans []dnsmessage.RR) string {
	var w []string
	for _, a := range ans {
		w = append(w, RscWrapper{Rsc: a}.String())
	}
	return strings.Join(w, "; ")
}
