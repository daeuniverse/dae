package dialer

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/proxy"
	"sync"
	"time"
)

var (
	UnexpectedFieldErr  = fmt.Errorf("unexpected field")
	InvalidParameterErr = fmt.Errorf("invalid parameters")
)

type Dialer struct {
	*GlobalOption
	instanceOption InstanceOption
	proxy.Dialer
	name     string
	protocol string
	link     string

	tcp4Latencies10     *LatenciesN
	tcp6Latencies10     *LatenciesN
	udp4Latencies10     *LatenciesN
	udp6Latencies10     *LatenciesN
	aliveDialerSetSetMu sync.Mutex
	// aliveDialerSetSet uses reference counting.
	tcp4AliveDialerSetSet AliveDialerSetSet
	tcp6AliveDialerSetSet AliveDialerSetSet
	udp4AliveDialerSetSet AliveDialerSetSet
	udp6AliveDialerSetSet AliveDialerSetSet

	tickerMu sync.Mutex
	ticker   *time.Ticker
}

type GlobalOption struct {
	Log            *logrus.Logger
	TcpCheckOption *TcpCheckOption
	UdpCheckOption *UdpCheckOption
	CheckInterval  time.Duration
}

type InstanceOption struct {
	CheckEnabled bool
}

type AliveDialerSetSet map[*AliveDialerSet]int

// NewDialer is for register in general.
func NewDialer(dialer proxy.Dialer, option *GlobalOption, iOption InstanceOption, name string, protocol string, link string) *Dialer {
	d := &Dialer{
		Dialer:          dialer,
		GlobalOption:    option,
		instanceOption:  iOption,
		name:            name,
		protocol:        protocol,
		link:            link,
		tcp4Latencies10: NewLatenciesN(10),
		tcp6Latencies10: NewLatenciesN(10),
		udp4Latencies10: NewLatenciesN(10),
		udp6Latencies10: NewLatenciesN(10),
		// Set a very big cycle to wait for init.
		ticker:                time.NewTicker(time.Hour),
		tcp4AliveDialerSetSet: make(AliveDialerSetSet),
		tcp6AliveDialerSetSet: make(AliveDialerSetSet),
		udp4AliveDialerSetSet: make(AliveDialerSetSet),
		udp6AliveDialerSetSet: make(AliveDialerSetSet),
	}
	if iOption.CheckEnabled {
		go d.aliveBackground()
	}
	return d
}

func (d *Dialer) Close() error {
	d.tickerMu.Lock()
	d.ticker.Stop()
	d.tickerMu.Unlock()
	return nil
}

func (d *Dialer) Name() string {
	return d.name
}

func (d *Dialer) Protocol() string {
	return d.protocol
}

func (d *Dialer) Link() string {
	return d.link
}
