package simpleobfs

import "github.com/daeuniverse/outbound/dialer"

func init() {
	dialer.FromLinkRegister("simpleobfs", NewSimpleObfs)
}
