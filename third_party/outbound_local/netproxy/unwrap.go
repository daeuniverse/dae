package netproxy

import "net"

// UnderlyingConnProvider exposes the wrapped inner net.Conn.
// Wrappers that want to participate in transport capability checks
// (for example TCP fast-path / offload) should implement this interface.
type UnderlyingConnProvider interface {
	UnderlyingConn() net.Conn
}

const unwrapTCPConnMaxDepth = 8

// UnwrapTCPConn resolves a concrete *net.TCPConn from a possibly wrapped
// connection by following UnderlyingConnProvider.
func UnwrapTCPConn(conn any) (*net.TCPConn, bool) {
	return unwrapTCPConnDepth(conn, 0)
}

func unwrapTCPConnDepth(conn any, depth int) (*net.TCPConn, bool) {
	if conn == nil || depth >= unwrapTCPConnMaxDepth {
		return nil, false
	}

	switch c := conn.(type) {
	case *net.TCPConn:
		return c, true
	case UnderlyingConnProvider:
		return unwrapTCPConnDepth(c.UnderlyingConn(), depth+1)
	default:
		return nil, false
	}
}
