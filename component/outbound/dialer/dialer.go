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

	collectionFineMu sync.Mutex
	collections      [4]*collection

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
	var collections [4]*collection
	for i := range collections {
		collections[i] = newCollection()
	}
	d := &Dialer{
		GlobalOption:   option,
		instanceOption: iOption,
		Dialer:         dialer,
		name:           name,
		protocol:       protocol,
		link:           link,
		collections:    collections,
		// Set a very big cycle to wait for init.
		ticker: time.NewTicker(time.Hour),
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
