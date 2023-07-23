package ws

import (
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

func init() {
	dialer.FromLinkRegister("http", NewWs)
}
