package tuic

import (
	"container/list"
	"context"
	"sync"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/tuic/common"
)

type clientRing struct {
	mu        sync.Mutex
	ring      *list.List
	current   *list.Element
	newClient func(capabilityCallback func(n int64)) *clientImpl
	reserved  int64
}

type clientRingNode struct {
	cli *clientImpl
	// capability is protected by quic RWMutex.
	capability int64
}

func newClientRing(newClient func(capabilityCallback func(n int64)) *clientImpl, reserved int64) *clientRing {
	ring := list.New().Init()
	return &clientRing{
		mu:        sync.Mutex{},
		ring:      ring,
		current:   nil,
		newClient: newClient,
		reserved:  reserved,
	}
}

func (r *clientRing) DialContextWithDialer(ctx context.Context, metadata *protocol.Metadata, dialer netproxy.Dialer, dialFn common.DialFunc) (conn netproxy.Conn, err error) {
	defer func() {
		r.ring.Len()
	}()
	r.mu.Lock()
	defer r.mu.Unlock()
	newCurrent := r.current
	err = r._tryNext(&newCurrent, func(node *clientRingNode) error {
		if node.capability != -1 && node.capability <= r.reserved {
			return common.ErrHoldOn
		}
		conn, err = node.cli.DialContextWithDialer(ctx, metadata, dialer, dialFn)
		return err
	})
	r.current = newCurrent
	return conn, err
}

func (r *clientRing) ListenPacketWithDialer(ctx context.Context, metadata *protocol.Metadata, dialer netproxy.Dialer, dialFn common.DialFunc) (conn netproxy.PacketConn, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	newCurrent := r.current
	err = r._tryNext(&newCurrent, func(node *clientRingNode) error {
		if node.capability != -1 && node.capability <= r.reserved {
			return common.ErrHoldOn
		}
		conn, err = node.cli.ListenPacketWithDialer(ctx, metadata, dialer, dialFn)
		return err
	})
	r.current = newCurrent
	return conn, err
}

func (r *clientRing) _tryNext(current **list.Element, f func(cli *clientRingNode) error) (err error) {
	var cli *clientRingNode
	if *current == nil {
		goto getNew
	}
	cli = (*current).Value.(*clientRingNode)
	err = f(cli)
	if err == nil {
		// OK.
		return nil
	}

	// Expected error: too many open streams.
	*current = (*current).Next()
	// NOTICE: Add the bellow code to reuse previous clients.
	{
		if *current == nil {
			*current = r.ring.Front()
		}
	}
	if *current == r.current {
		if err == common.ErrTooManyOpenStreams ||
			err == common.ErrClientClosed ||
			err == common.ErrHoldOn {
			goto getNew
		}
		// Not the expected error.
		return err
	}

	return r._tryNext(current, f)

getNew:
	newNode := &clientRingNode{
		cli:        nil,
		capability: -1,
	}
	newCli := r.newClient(func(n int64) { newNode.capability = n })
	newNode.cli = newCli
	r.current = r._insertAfterCurrent(newNode)
	*current = r.current
	return f(newNode)
}

func (r *clientRing) _insertAfterCurrent(node *clientRingNode) (elem *list.Element) {
	if r.current == nil {
		elem = r.ring.PushBack(node)
		r.current = elem
	} else {
		elem = r.ring.InsertAfter(node, r.current)
	}
	node.cli.setOnClose(func() {
		r.passiveRemove(elem)
	})
	return elem
}

func (r *clientRing) passiveRemove(elem *list.Element) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if elem.Value == nil {
		// Removed.
		return
	}
	elem.Value = nil
	if r.current == elem {
		r.current = elem.Next()
	}
	r.ring.Remove(elem)
}
