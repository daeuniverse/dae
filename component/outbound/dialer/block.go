/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/softwind/netproxy"
)

func NewBlockDialer(option *GlobalOption, dialCallback func()) (netproxy.Dialer, *Property) {
	d, _p := D.NewBlockDialer(&option.ExtraOption, dialCallback)
	return d, &Property{
		Property:        *_p,
		SubscriptionTag: "",
	}
}
