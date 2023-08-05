package dialer

import (
	"github.com/daeuniverse/softwind/netproxy"
	softwindDirect "github.com/daeuniverse/softwind/protocol/direct"
)

func NewDirectDialer(option *GlobalOption, fullcone bool) (netproxy.Dialer, *Property) {
	property := &Property{
		Name:     "direct",
		Address:  "",
		Protocol: "",
		Link:     "",
	}
	if fullcone {
		return softwindDirect.FullconeDirect, property
	} else {
		return softwindDirect.SymmetricDirect, property
	}
}
