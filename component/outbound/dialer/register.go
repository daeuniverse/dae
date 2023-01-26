/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, mzz2017 (mzz@tuta.io). All rights reserved.
 */

package dialer

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"net/url"
)

type FromLinkCreator func(log *logrus.Logger, link string) (dialer *Dialer, err error)

var fromLinkCreators = make(map[string]FromLinkCreator)

func FromLinkRegister(name string, creator FromLinkCreator) {
	fromLinkCreators[name] = creator
}

func NewFromLink(log *logrus.Logger, link string) (dialer *Dialer, err error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	if creator, ok := fromLinkCreators[u.Scheme]; ok {
		return creator(log, link)
	} else {
		return nil, fmt.Errorf("unexpected link type: %v", u.Scheme)
	}
}
