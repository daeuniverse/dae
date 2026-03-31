package common

import (
	"github.com/daeuniverse/outbound/protocol/tuic/congestion"
	"github.com/olicesx/quic-go"
)

const (
	InitialStreamReceiveWindow     = 2 * 1024 * 1024  // 2 MB
	MaxStreamReceiveWindow         = 32 * 1024 * 1024 // 32 MB
	InitialConnectionReceiveWindow = 32 * 1024 * 1024 // 32 MB
	MaxConnectionReceiveWindow     = 64 * 1024 * 1024 // 64 MB
)

func SetCongestionController(quicConn quic.Connection, cc string, cwnd int) {
	switch cc {
	default:
		fallthrough
	case "bbr":
		congestion.UseBBR(quicConn)
	}
}
