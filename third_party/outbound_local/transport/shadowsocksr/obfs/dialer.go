package obfs

import (
	"context"
	"errors"
	"fmt"

	"github.com/daeuniverse/outbound/netproxy"
)

type Dialer struct {
	NextDialer netproxy.Dialer
	param      *ObfsParam

	constructor *constructor
}
type ObfsParam struct {
	ObfsHost  string
	ObfsPort  uint16
	Obfs      string
	ObfsParam string
}

func NewDialer(nextDialer netproxy.Dialer, param *ObfsParam) (*Dialer, error) {

	constructor := NewObfs(param.Obfs)
	if constructor == nil {
		return nil, errors.New("unsupported protocol type: " + param.Obfs)
	}

	d := &Dialer{
		NextDialer:  nextDialer,
		param:       param,
		constructor: constructor,
	}
	return d, nil
}

func (d *Dialer) ObfsOverhead() int {
	return d.constructor.Overhead
}

func (d *Dialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		conn, err := d.NextDialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		obfs := d.constructor.New()
		if obfs == nil {
			return nil, errors.New("unsupported protocol type: " + d.param.Obfs)
		}
		obfsServerInfo := &ServerInfo{
			Host:  d.param.ObfsHost,
			Port:  d.param.ObfsPort,
			Param: d.param.ObfsParam,
		}
		obfs.SetData(obfs.GetData())
		obfs.SetServerInfo(obfsServerInfo)

		return NewConn(conn, obfs)
	case "udp":
		return d.NextDialer.DialContext(ctx, network, addr)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}
