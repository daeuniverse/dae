package netproxy

import (
	"context"
	"time"
)

var (
	DialTimeout = 10 * time.Second
)

func NewDialTimeoutContextFrom(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, DialTimeout)
}

func NewDialTimeoutContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), DialTimeout)
}

// A Dialer is a means to establish a connection.
// Custom dialers should also implement ContextDialer.
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (c Conn, err error)
}
