package tls

import "github.com/daeuniverse/dae/component/outbound/dialer"

func init() {
	dialer.FromLinkRegister("tls", NewTls)
}
