/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, v2rayA Organization <team@v2raya.org>
 */

package dialer

import (
	"github.com/mzz2017/softwind/netproxy"
	"net"
)

type blockDialer struct {
	DialCallback func()
}

func (d *blockDialer) DialTcp(addr string) (c netproxy.Conn, err error) {
	d.DialCallback()
	return nil, net.ErrClosed
}
func (d *blockDialer) DialUdp(addr string) (c netproxy.PacketConn, err error) {
	d.DialCallback()
	return nil, net.ErrClosed
}

func NewBlockDialer(option *GlobalOption, dialCallback func()) *Dialer {
	return NewDialer(&blockDialer{DialCallback: dialCallback}, option, InstanceOption{CheckEnabled: false}, "block", "block", "")
}
