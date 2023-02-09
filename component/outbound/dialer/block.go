/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, v2rayA Organization <team@v2raya.org>
 */

package dialer

import (
	"net"
)

type blockDialer struct {
	DialCallback func()
}

func (d *blockDialer) Dial(network string, addr string) (c net.Conn, err error) {
	d.DialCallback()
	return nil, net.ErrClosed
}

func NewBlockDialer(option *GlobalOption, dialCallback func()) *Dialer {
	return NewDialer(&blockDialer{DialCallback: dialCallback}, option, InstanceOption{CheckEnabled: false}, "block", "block", "")
}
