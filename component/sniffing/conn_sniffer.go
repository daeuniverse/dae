/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"errors"
	"net"
	"strings"
	"sync"
	"time"
)

type ConnSniffer struct {
	net.Conn
	sniffer *Sniffer

	mu sync.Mutex
}

func NewConnSniffer(conn net.Conn, snifferBufSize int) *ConnSniffer {
	s := &ConnSniffer{
		Conn:    conn,
		sniffer: NewStreamSniffer(conn, snifferBufSize),
	}
	return s
}
func (s *ConnSniffer) SniffTcp() (d string, err error) {
	s.Conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	defer s.Conn.SetReadDeadline(time.Time{})
	return s.sniffer.SniffTcp()
}

func (s *ConnSniffer) Read(p []byte) (n int, err error) {
	s.mu.Lock()
	n, err = s.sniffer.Read(p)
	s.mu.Unlock()
	return n, err
}

func (s *ConnSniffer) Close() (err error) {
	var errs []string
	if err = s.sniffer.Close(); err != nil {
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
