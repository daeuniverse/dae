/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"

	"github.com/daeuniverse/outbound/netproxy"
	transportgrpc "github.com/daeuniverse/outbound/transport/grpc"
	transportmeek "github.com/daeuniverse/outbound/transport/meek"
)

type transportCacheScopedDialer struct {
	netproxy.Dialer
	namespace string
}

type transportCacheNamespaceProvider interface {
	TransportCacheNamespace() string
}

var transportCacheNamespaceSeq atomic.Uint64

func newTransportCacheNamespace() string {
	return fmt.Sprintf("dae-reload-%d", transportCacheNamespaceSeq.Add(1))
}

func scopeTransportCacheDialer(d netproxy.Dialer, namespace string) netproxy.Dialer {
	if d == nil || namespace == "" {
		return d
	}
	if scoped, ok := d.(transportCacheNamespaceProvider); ok && scoped.TransportCacheNamespace() == namespace {
		return d
	}
	return &transportCacheScopedDialer{Dialer: d, namespace: namespace}
}

func (d *transportCacheScopedDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	return d.Dialer.DialContext(ctx, network, addr)
}

func (d *transportCacheScopedDialer) LookupIPAddr(ctx context.Context, network, host string) ([]net.IPAddr, error) {
	resolver, ok := d.Dialer.(interface {
		LookupIPAddr(context.Context, string, string) ([]net.IPAddr, error)
	})
	if !ok {
		return net.DefaultResolver.LookupIPAddr(ctx, host)
	}
	return resolver.LookupIPAddr(ctx, network, host)
}

func (d *transportCacheScopedDialer) TransportCacheNamespace() string {
	return d.namespace
}

func CleanupTransportCacheNamespace(namespace string) {
	if namespace == "" {
		return
	}
	transportgrpc.CleanScopedClientConnectionCache(namespace)
	transportmeek.CleanScopedRoundTripperCache(namespace)
}
