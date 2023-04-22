/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"fmt"
	"net/url"

	"github.com/daeuniverse/dae/common"
)

type FromLinkCreator func(gOption *GlobalOption, iOption InstanceOption, link string) (dialer *Dialer, err error)

var fromLinkCreators = make(map[string]FromLinkCreator)

func FromLinkRegister(name string, creator FromLinkCreator) {
	fromLinkCreators[name] = creator
}

func NewFromLink(gOption *GlobalOption, iOption InstanceOption, link string) (dialer *Dialer, err error) {
	/// Get overwritten name.
	overwrittenName, link := common.GetTagFromLinkLikePlaintext(link)
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	if creator, ok := fromLinkCreators[u.Scheme]; ok {
		node, err := creator(gOption, iOption, link)
		if err != nil {
			return nil, err
		}
		// Overwrite node name using user given tag.
		if overwrittenName != "" {
			node.property.Name = overwrittenName
		}
		return node, err
	} else {
		return nil, fmt.Errorf("unexpected link type: %v", u.Scheme)
	}
}
