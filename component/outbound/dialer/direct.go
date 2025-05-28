/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

func NewDirectDialer(option *GlobalOption, fullcone bool) (netproxy.Dialer, *Property) {
	d, _p := D.NewDirectDialer(&option.ExtraOption, fullcone)
	return d, &Property{
		Property:        *_p,
		SubscriptionTag: "",
	}
}
