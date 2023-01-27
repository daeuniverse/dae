/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, mzz2017 <mzz@tuta.io>
 */

package dialer

import (
	"fmt"
	"net/url"
)

type FromLinkCreator func(option *GlobalOption, link string) (dialer *Dialer, err error)

var fromLinkCreators = make(map[string]FromLinkCreator)

func FromLinkRegister(name string, creator FromLinkCreator) {
	fromLinkCreators[name] = creator
}

func NewFromLink(option *GlobalOption, link string) (dialer *Dialer, err error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	if creator, ok := fromLinkCreators[u.Scheme]; ok {
		return creator(option, link)
	} else {
		return nil, fmt.Errorf("unexpected link type: %v", u.Scheme)
	}
}
