package tls

import "github.com/daeuniverse/outbound/dialer"

func init() {
	dialer.FromLinkRegister("tls", NewTls)
	dialer.FromLinkRegister("utls", NewTls)
}
