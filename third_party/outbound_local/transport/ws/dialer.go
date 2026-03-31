package ws

import (
	"github.com/daeuniverse/outbound/dialer"
)

func init() {
	dialer.FromLinkRegister("ws", NewWs)
	dialer.FromLinkRegister("wss", NewWs)
}
