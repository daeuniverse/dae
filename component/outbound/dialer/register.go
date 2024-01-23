/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/softwind/protocol/direct"
)

func NewFromLink(gOption *GlobalOption, iOption InstanceOption, link string, subscriptionTag string) (*Dialer, error) {
	d, _p, err := D.NewNetproxyDialerFromLink(direct.SymmetricDirect, &gOption.ExtraOption, link)
	if err != nil {
		return nil, err
	}
	p := Property{
		Property:        *_p,
		SubscriptionTag: subscriptionTag,
	}
	return NewDialer(d, gOption, iOption, &p), nil
}
