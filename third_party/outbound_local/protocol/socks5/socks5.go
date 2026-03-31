// https://www.rfc-editor.org/rfc/rfc1928

// socks5 client:
// https://github.com/golang/net/tree/master/proxy
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package socks5 implements a socks5 proxy.

// Modified from https://github.com/nadoo/glider/tree/v0.16.2

package socks5

import (
	"net/url"

	"github.com/daeuniverse/outbound/netproxy"
)

// Version is socks5 version number.
const Version = 5

// Socks5 is a base socks5 struct.
type Socks5 struct {
	dialer   netproxy.Dialer
	addr     string
	user     string
	password string
}

// NewSocks5 returns a Proxy that makes SOCKS v5 connections to the given address.
// with an optional username and password. (RFC 1928)
func NewSocks5(s string, d netproxy.Dialer) (*Socks5, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}

	addr := u.Host
	user := u.User.Username()
	pass, _ := u.User.Password()

	h := &Socks5{
		dialer:   d,
		addr:     addr,
		user:     user,
		password: pass,
	}

	return h, nil
}
