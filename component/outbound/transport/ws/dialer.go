package ws

import (
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

func init() {
	dialer.FromLinkRegister("ws", NewWs)
	dialer.FromLinkRegister("wss", NewWs)
}
