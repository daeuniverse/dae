/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, v2rayA Organization <team@v2raya.org>
 */

package dialer

import (
	"fmt"
	"net/url"
	"strings"
)

type FromLinkCreator func(gOption *GlobalOption, iOption InstanceOption, link string) (dialer *Dialer, err error)

var fromLinkCreators = make(map[string]FromLinkCreator)

func FromLinkRegister(name string, creator FromLinkCreator) {
	fromLinkCreators[name] = creator
}

func NewFromLink(gOption *GlobalOption, iOption InstanceOption, link string) (dialer *Dialer, err error) {
	/// Get overwritten name.
	var overwrittenName string
	iColon := strings.Index(link, ":")
	if iColon == -1 {
		goto parseUrl
	}
	// If first colon is like "://" in "scheme://linkbody", no tag is present.
	if strings.HasPrefix(link[iColon:], "://") {
		goto parseUrl
	}
	// Else tag is the part before colon.
	overwrittenName = link[:iColon]
	link = link[iColon+1:]

parseUrl:
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
			node.name = overwrittenName
		}
		return node, err
	} else {
		return nil, fmt.Errorf("unexpected link type: %v", u.Scheme)
	}
}
