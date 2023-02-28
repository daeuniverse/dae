package dialer

import (
	softwindDirect "github.com/mzz2017/softwind/protocol/direct"
)

func NewDirectDialer(option *GlobalOption, fullcone bool) *Dialer {
	property := Property{
		Name:     "direct",
		Address:  "",
		Protocol: "",
		Link:     "",
	}
	if fullcone {
		return NewDialer(softwindDirect.FullconeDirect, option, InstanceOption{CheckEnabled: false}, property)
	} else {
		return NewDialer(softwindDirect.SymmetricDirect, option, InstanceOption{CheckEnabled: false}, property)
	}
}
