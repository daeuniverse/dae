package protocol

import (
	"fmt"
	"strconv"

	"github.com/daeuniverse/outbound/netproxy"
)

type Creator func(nextDialer netproxy.Dialer, header Header) (netproxy.Dialer, error)

var Mapper = make(map[string]Creator)

func Register(name string, c Creator) {
	Mapper[name] = c
}

func NewDialer(name string, nextDialer netproxy.Dialer, header Header) (netproxy.Dialer, error) {
	creator, ok := Mapper[name]
	if !ok {
		return nil, fmt.Errorf("no conn creator registered for %v", strconv.Quote(name))
	}
	return creator(nextDialer, header)
}
