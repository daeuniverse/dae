package protocol

import (
	"fmt"
	"strings"

	"github.com/daeuniverse/outbound/common"
)

var (
	ErrFailAuth     = fmt.Errorf("fail to authenticate")
	ErrReplayAttack = fmt.Errorf("replay attack")
)

type Protocol string

const (
	ProtocolVMessTCP     Protocol = "vmess"
	ProtocolVMessTlsGrpc Protocol = "vmess+tls+grpc"
	ProtocolShadowsocks  Protocol = "shadowsocks"
	ProtocolJuicity      Protocol = "juicity"
)

func (p Protocol) Valid() bool {
	switch p {
	case ProtocolVMessTCP, ProtocolVMessTlsGrpc, ProtocolShadowsocks, ProtocolJuicity:
		return true
	default:
		return false
	}
}

func (p Protocol) WithTLS() bool {
	return common.StringsHas(strings.Split(string(p), "+"), "tls")
}
