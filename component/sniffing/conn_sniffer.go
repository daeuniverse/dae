/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, v2rayA Organization <team@v2raya.org>
 */

package sniffing

import (
	"errors"
	"net"
	"strings"
	"sync"
)

type ConnSniffer struct {
	net.Conn
	*Sniffer

	mu sync.Mutex
}

func NewConnSniffer(conn net.Conn, snifferBufSize int) *ConnSniffer {
	s := &ConnSniffer{
		Conn:    conn,
		Sniffer: NewStreamSniffer(conn, snifferBufSize),
	}
	return s
}

func (s *ConnSniffer) Read(p []byte) (n int, err error) {
	s.mu.Lock()
	n, err = s.Sniffer.Read(p)
	s.mu.Unlock()
	return n, err
}

func (s *ConnSniffer) Close() (err error) {
	var errs []string
	if err = s.Sniffer.Close(); err != nil {
		errs = append(errs, err.Error())
	}
	if err = s.Conn.Close(); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}
