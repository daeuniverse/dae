package common

import (
	"context"
	"net"

	outbounderrors "github.com/daeuniverse/outbound/common/errors"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/olicesx/quic-go"
)

var (
	ErrClientClosed       = outbounderrors.ErrClientClosed
	ErrTooManyOpenStreams = outbounderrors.ErrStreamExhausted
	ErrHoldOn             = outbounderrors.ErrOperationHold
)

type DialFunc func(ctx context.Context, dialer netproxy.Dialer) (transport *quic.Transport, addr net.Addr, err error)

type Client interface {
	DialContextWithDialer(ctx context.Context, metadata *protocol.Metadata, dialer netproxy.Dialer, dialFn DialFunc) (netproxy.Conn, error)
	ListenPacketWithDialer(ctx context.Context, metadata *protocol.Metadata, dialer netproxy.Dialer, dialFn DialFunc) (netproxy.PacketConn, error)
	OpenStreams() int64
	Close()
}

type UdpRelayMode uint8

const (
	QUIC UdpRelayMode = iota
	NATIVE
)

// IsTemporaryError checks if an error is temporary and should not close the connection
func IsTemporaryError(err error) bool {
	return outbounderrors.IsTemporaryError(err)
}
