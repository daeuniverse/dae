package dialer

import (
	"context"
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
	collections      [6]*collection

	tickerMu sync.Mutex
	ticker   *time.Ticker
	checkCh  chan time.Time
	ctx      context.Context
	cancel   context.CancelFunc
}

type GlobalOption struct {
	Log               *logrus.Logger
	TcpCheckOptionRaw TcpCheckOptionRaw // Lazy parse
	CheckDnsOptionRaw CheckDnsOptionRaw // Lazy parse
	CheckInterval     time.Duration
	CheckTolerance    time.Duration
	CheckDnsTcp       bool
}

type InstanceOption struct {
	CheckEnabled bool
}

type AliveDialerSetSet map[*AliveDialerSet]int

// NewDialer is for register in general.
func NewDialer(dialer proxy.Dialer, option *GlobalOption, iOption InstanceOption, name string, protocol string, link string) *Dialer {
	var collections [6]*collection
	for i := range collections {
		collections[i] = newCollection()
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &Dialer{
		GlobalOption:     option,
		instanceOption:   iOption,
		Dialer:           dialer,
		name:             name,
		protocol:         protocol,
		link:             link,
		collectionFineMu: sync.Mutex{},
		collections:      collections,
		tickerMu:         sync.Mutex{},
		ticker:           nil,
		checkCh:          make(chan time.Time, 1),
		ctx:              ctx,
		cancel:           cancel,
	}
	if iOption.CheckEnabled {
		go d.aliveBackground()
	}
	return d
}

func (d *Dialer) Close() error {
	d.cancel()
	d.tickerMu.Lock()
	if d.ticker != nil {
		d.ticker.Stop()
	}
	d.tickerMu.Unlock()
	close(d.checkCh)
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
