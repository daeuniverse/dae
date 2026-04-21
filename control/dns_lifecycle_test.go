/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	stderrors "errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
	"github.com/olicesx/quic-go"
	"github.com/olicesx/quic-go/congestion"
	"github.com/stretchr/testify/require"
)

type trackingRoundTripper struct {
	closeIdleCalls atomic.Int32
}

func (rt *trackingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, stderrors.New("unexpected RoundTrip")
}

func (rt *trackingRoundTripper) CloseIdleConnections() {
	rt.closeIdleCalls.Add(1)
}

type fakeEarlyConnection struct {
	ctx               context.Context
	handshakeComplete chan struct{}
	closeCalls        atomic.Int32
	openStreamSync    func(context.Context) (quic.Stream, error)
}

func newFakeEarlyConnection() *fakeEarlyConnection {
	handshakeComplete := make(chan struct{})
	close(handshakeComplete)
	return &fakeEarlyConnection{
		ctx:               context.Background(),
		handshakeComplete: handshakeComplete,
	}
}

func (c *fakeEarlyConnection) AcceptStream(context.Context) (quic.Stream, error) {
	return nil, stderrors.New("unexpected AcceptStream")
}

func (c *fakeEarlyConnection) AcceptUniStream(context.Context) (quic.ReceiveStream, error) {
	return nil, stderrors.New("unexpected AcceptUniStream")
}

func (c *fakeEarlyConnection) OpenStream() (quic.Stream, error) {
	return nil, stderrors.New("unexpected OpenStream")
}

func (c *fakeEarlyConnection) OpenStreamSync(ctx context.Context) (quic.Stream, error) {
	if c.openStreamSync != nil {
		return c.openStreamSync(ctx)
	}
	return nil, stderrors.New("unexpected OpenStreamSync")
}

func (c *fakeEarlyConnection) OpenUniStream() (quic.SendStream, error) {
	return nil, stderrors.New("unexpected OpenUniStream")
}

func (c *fakeEarlyConnection) OpenUniStreamSync(context.Context) (quic.SendStream, error) {
	return nil, stderrors.New("unexpected OpenUniStreamSync")
}

func (c *fakeEarlyConnection) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func (c *fakeEarlyConnection) RemoteAddr() net.Addr {
	return &net.UDPAddr{}
}

func (c *fakeEarlyConnection) CloseWithError(quic.ApplicationErrorCode, string) error {
	c.closeCalls.Add(1)
	return nil
}

func (c *fakeEarlyConnection) Context() context.Context {
	if c.ctx != nil {
		return c.ctx
	}
	return context.Background()
}

func (c *fakeEarlyConnection) ConnectionState() quic.ConnectionState {
	return quic.ConnectionState{}
}

func (c *fakeEarlyConnection) SendDatagram([]byte) error {
	return stderrors.New("unexpected SendDatagram")
}

func (c *fakeEarlyConnection) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, stderrors.New("unexpected ReceiveDatagram")
}

func (c *fakeEarlyConnection) SetCongestionControl(congestion.CongestionControl) {}

func (c *fakeEarlyConnection) HandshakeComplete() <-chan struct{} {
	return c.handshakeComplete
}

func (c *fakeEarlyConnection) NextConnection(context.Context) (quic.Connection, error) {
	return nil, stderrors.New("unexpected NextConnection")
}

func TestDoHForwardDNSRefreshesOnceUnderContention(t *testing.T) {
	origSend := sendHttpDNSFunc
	t.Cleanup(func() {
		sendHttpDNSFunc = origSend
	})

	oldTransport := &trackingRoundTripper{}
	newTransport := &trackingRoundTripper{}
	oldClient := &http.Client{Transport: oldTransport}
	newClient := &http.Client{Transport: newTransport}

	var factoryCalls atomic.Int32
	var oldClientCalls atomic.Int32
	var newClientCalls atomic.Int32
	sendHttpDNSFunc = func(client *http.Client, target string, upstream *dns.Upstream, data []byte) (*dnsmessage.Msg, error) {
		switch client {
		case oldClient:
			oldClientCalls.Add(1)
			return nil, stderrors.New("dial failed")
		case newClient:
			newClientCalls.Add(1)
			return &dnsmessage.Msg{}, nil
		default:
			t.Fatalf("unexpected client: %p", client)
			return nil, nil
		}
	}

	d := &DoH{
		client: oldClient,
		clientFactory: func() *http.Client {
			factoryCalls.Add(1)
			return newClient
		},
	}

	const workers = 16
	start := make(chan struct{})
	errCh := make(chan error, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			<-start
			_, err := d.ForwardDNS(context.Background(), []byte{0, 0})
			errCh <- err
		}()
	}

	close(start)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		require.NoError(t, err)
	}
	require.EqualValues(t, 1, factoryCalls.Load())
	require.EqualValues(t, 1, oldTransport.closeIdleCalls.Load())
	require.GreaterOrEqual(t, oldClientCalls.Load(), int32(1))
	require.GreaterOrEqual(t, newClientCalls.Load(), int32(1))
	require.Same(t, newClient, d.client)
}

func TestDoHForwardDNSReturnsErrClosedAfterClose(t *testing.T) {
	origSend := sendHttpDNSFunc
	t.Cleanup(func() {
		sendHttpDNSFunc = origSend
	})

	transport := &trackingRoundTripper{}
	var sendCalls atomic.Int32
	sendHttpDNSFunc = func(client *http.Client, target string, upstream *dns.Upstream, data []byte) (*dnsmessage.Msg, error) {
		sendCalls.Add(1)
		return nil, stderrors.New("unexpected send")
	}

	d := &DoH{
		client: &http.Client{Transport: transport},
	}

	require.NoError(t, d.Close())
	_, err := d.ForwardDNS(context.Background(), []byte{0, 0})
	require.ErrorIs(t, err, net.ErrClosed)
	require.EqualValues(t, 1, transport.closeIdleCalls.Load())
	require.Zero(t, sendCalls.Load())
	require.Nil(t, d.client)
}

func TestDoQForwardDNSReturnsErrClosedWhenClosedDuringDial(t *testing.T) {
	origSend := sendStreamDNSFunc
	t.Cleanup(func() {
		sendStreamDNSFunc = origSend
	})
	sendStreamDNSFunc = func(stream io.ReadWriter, data []byte) (*dnsmessage.Msg, error) {
		t.Fatal("sendStreamDNS should not be reached when dial races with Close")
		return nil, nil
	}

	dialStarted := make(chan struct{})
	releaseDial := make(chan struct{})
	conn := newFakeEarlyConnection()
	d := &DoQ{
		connectionFactory: func(ctx context.Context) (quic.EarlyConnection, error) {
			close(dialStarted)
			<-releaseDial
			return conn, nil
		},
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := d.ForwardDNS(context.Background(), []byte{0, 0})
		errCh <- err
	}()

	<-dialStarted
	require.NoError(t, d.Close())
	close(releaseDial)

	err := <-errCh
	require.ErrorIs(t, err, net.ErrClosed)
	require.EqualValues(t, 1, conn.closeCalls.Load())
	require.Nil(t, d.connection)
}

func TestDoQForwardDNSReturnsErrClosedAfterClose(t *testing.T) {
	var dialCalls atomic.Int32
	d := &DoQ{
		connectionFactory: func(context.Context) (quic.EarlyConnection, error) {
			dialCalls.Add(1)
			return newFakeEarlyConnection(), nil
		},
	}

	require.NoError(t, d.Close())
	_, err := d.ForwardDNS(context.Background(), []byte{0, 0})
	require.ErrorIs(t, err, net.ErrClosed)
	require.Zero(t, dialCalls.Load())
}
