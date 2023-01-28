/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, v2rayA Organization <team@v2raya.org>
 */

package dialer

import (
	"net"
)

type blockDialer struct{}

func (*blockDialer) Dial(network string, addr string) (c net.Conn, err error) {
	return nil, net.ErrClosed
}

func NewBlockDialer(option *GlobalOption) *Dialer {
	return NewDialer(&blockDialer{}, option, InstanceOption{Check: false}, true, "block", "block", "")
}
