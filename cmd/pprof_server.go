/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"
)

// startPprofServer serves net/http/pprof on the loopback interface.
//
// The listener is created before the serving goroutine starts so a bind
// failure reaches the caller. Both the startup path and the reload path used
// to hide that error inside a bare goroutine, which made a pprof_port that
// never came up indistinguishable from one that was never configured.
//
// The returned server is served on an already-bound listener, so the goroutine
// only ever observes a shutdown or an accept failure; capturing the concrete
// *http.Server keeps a later refresh from swapping the pointer under it.
func startPprofServer(port uint16) (*http.Server, error) {
	addr := "localhost:" + strconv.Itoa(int(port))
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen pprof on %s: %w", addr, err)
	}
	server := &http.Server{}
	go func() {
		_ = server.Serve(listener)
	}()
	return server, nil
}

// stopPprofServer shuts the server down, if any, and clears the slot so a
// later start cannot observe a half-closed server.
func stopPprofServer(server **http.Server) {
	if server == nil || *server == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	_ = (*server).Shutdown(ctx)
	cancel()
	*server = nil
}
