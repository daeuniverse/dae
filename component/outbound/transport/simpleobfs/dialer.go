package simpleobfs

import "github.com/daeuniverse/dae/component/outbound/dialer"

func init() {
	dialer.FromLinkRegister("simpleobfs", NewSimpleObfs)
}
