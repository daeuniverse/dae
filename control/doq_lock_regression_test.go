/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"
	"time"

	"github.com/olicesx/quic-go"
)

type blockingCloseEarlyConn struct {
	stubEarlyConn
	started chan struct{}
	release <-chan struct{}
}

func (c *blockingCloseEarlyConn) CloseWithError(quic.ApplicationErrorCode, string) error {
	close(c.started)
	<-c.release
	c.closed.Add(1)
	return nil
}

func TestDoQInstallClosesLosingConnectionOutsideLock(t *testing.T) {
	winner := &stubEarlyConn{}
	release := make(chan struct{})
	loser := &blockingCloseEarlyConn{
		started: make(chan struct{}),
		release: release,
	}
	d := &DoQ{connection: winner}

	type installResult struct {
		connection quic.EarlyConnection
		err        error
	}
	installed := make(chan installResult, 1)
	go func() {
		connection, err := d.installConnection(loser)
		installed <- installResult{connection: connection, err: err}
	}()

	select {
	case <-loser.started:
	case <-time.After(time.Second):
		t.Fatal("losing connection close did not start")
	}

	lockAcquired := make(chan bool, 1)
	go func() {
		d.mu.Lock()
		connectionPresent := d.connection != nil
		d.mu.Unlock()
		lockAcquired <- connectionPresent
	}()
	select {
	case connectionPresent := <-lockAcquired:
		if !connectionPresent {
			t.Fatal("winning connection disappeared during install race")
		}
	case <-time.After(time.Second):
		close(release)
		<-installed
		t.Fatal("DoQ mutex remained held during losing connection close")
	}

	close(release)
	result := <-installed
	if result.err != nil {
		t.Fatalf("installConnection: %v", result.err)
	}
	if result.connection != winner {
		t.Fatal("install race did not keep the winning connection")
	}
	if got := loser.closed.Load(); got != 1 {
		t.Fatalf("losing connection close count = %d, want 1", got)
	}
}
