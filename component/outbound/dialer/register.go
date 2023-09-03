/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/softwind/netproxy"
	"github.com/daeuniverse/softwind/protocol/direct"
)

type FromLinkCreator func(gOption *GlobalOption, nextDialer netproxy.Dialer, link string) (dialer netproxy.Dialer, property *Property, err error)

var fromLinkCreators = make(map[string]FromLinkCreator)

func FromLinkRegister(name string, creator FromLinkCreator) {
	fromLinkCreators[name] = creator
}

func NewFromLink(gOption *GlobalOption, iOption InstanceOption, link string) (*Dialer, error) {
	/// Get overwritten name.
	overwrittenName, linklike := common.GetTagFromLinkLikePlaintext(link)
	links := strings.Split(linklike, "->")
	d := direct.SymmetricDirect
	p := &Property{
		Name:     "",
		Address:  "",
		Protocol: "",
		Link:     link,
	}
	for i := len(links) - 1; i >= 0; i-- {
		link := strings.TrimSpace(links[i])
		u, err := url.Parse(link)
		if err != nil {
			return nil, err
		}
		creator, ok := fromLinkCreators[u.Scheme]
		if !ok {
			return nil, fmt.Errorf("unexpected link type: %v", u.Scheme)
		}
		var _property *Property
		d, _property, err = creator(gOption, d, link)
		if err != nil {
			return nil, fmt.Errorf("create %v: %w", link, err)
		}
		if p.Name == "" {
			p.Name = _property.Name
		} else {
			p.Name = _property.Name + "->" + p.Name
		}
		if p.Protocol == "" {
			p.Protocol = _property.Protocol
		} else {
			p.Protocol = _property.Protocol + "->" + p.Protocol
		}
		if p.Address == "" {
			p.Address = _property.Address
		} else {
			p.Address = _property.Address + "->" + p.Address
		}
	}
	if overwrittenName != "" {
		p.Name = overwrittenName
	}
	node := NewDialer(d, gOption, iOption, p)
	return node, nil
}
