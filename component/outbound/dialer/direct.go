/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

func NewDirectDialer(option *GlobalOption, fullcone bool) (netproxy.Dialer, *Property) {
	var d netproxy.Dialer
	if fullcone {
		d = option.FullconeDirectDialer
	} else {
		d = option.DirectDialer
	}
	var p *D.Property
	if d == nil {
		d, p = D.NewDirectDialer(&option.ExtraOption, fullcone)
	} else {
		p = &D.Property{Name: "direct"}
	}
	return d, &Property{
		Property:        *p,
		SubscriptionTag: "",
	}
}
