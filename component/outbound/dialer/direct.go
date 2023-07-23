package dialer

import (
	"github.com/mzz2017/softwind/netproxy"
	softwindDirect "github.com/mzz2017/softwind/protocol/direct"
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
