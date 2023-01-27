/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, mzz2017 (mzz@tuta.io). All rights reserved.
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
	return newDialer(&blockDialer{}, option, true, "block", "block", "")
}
