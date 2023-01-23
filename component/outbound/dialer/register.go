/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, mzz2017 (mzz@tuta.io). All rights reserved.
 */

package dialer

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"net/url"
)

type FromLinkCreator func(link string) (dialer *Dialer, err error)

var fromLinkCreators = make(map[string]FromLinkCreator)

func FromLinkRegister(name string, creator FromLinkCreator) {
	fromLinkCreators[name] = creator
}

func NewFromLink(link string) (dialer *Dialer, err error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	if creator, ok := fromLinkCreators[u.Scheme]; ok {
		return creator(link)
	} else {
		return nil, fmt.Errorf("unexpected link type: %v", u.Scheme)
	}
}

type FromClashCreator func(clashObj *yaml.Node) (dialer *Dialer, err error)

var fromClashCreators = make(map[string]FromClashCreator)

func FromClashRegister(name string, creator FromClashCreator) {
	fromClashCreators[name] = creator
}

func NewFromClash(clashObj *yaml.Node) (dialer *Dialer, err error) {
	preUnload := make(map[string]interface{})
	if err := clashObj.Decode(&preUnload); err != nil {
		return nil, err
	}
	name, _ := preUnload["type"].(string)
	if creator, ok := fromClashCreators[name]; ok {
		return creator(clashObj)
	} else {
		return nil, fmt.Errorf("unexpected link type: %v", name)
	}
}
