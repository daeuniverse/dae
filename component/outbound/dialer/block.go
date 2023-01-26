/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, mzz2017 (mzz@tuta.io). All rights reserved.
 */

package dialer

import (
	"github.com/sirupsen/logrus"
	"net"
)

type blockDialer struct{}

func (*blockDialer) Dial(network string, addr string) (c net.Conn, err error) {
	return nil, net.ErrClosed
}

func NewBlockDialer(log *logrus.Logger) *Dialer {
	return newDialer(&blockDialer{}, log, true, "block", "block", "")
}
