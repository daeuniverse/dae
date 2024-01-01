package dialer

import (
	"context"
	"fmt"
	"sync"
	"time"

	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/softwind/netproxy"
	"github.com/sirupsen/logrus"
)

var (
	UnexpectedFieldErr  = fmt.Errorf("unexpected field")
	InvalidParameterErr = fmt.Errorf("invalid parameters")
)

type Dialer struct {
	*GlobalOption
	InstanceOption
	netproxy.Dialer
	property *Property

	collectionFineMu sync.Mutex
	collections      [6]*collection

	tickerMu sync.Mutex
	ticker   *time.Ticker
	checkCh  chan time.Time
	ctx      context.Context
	cancel   context.CancelFunc
}

type GlobalOption struct {
	D.ExtraOption
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

type Property struct {
	D.Property
	SubscriptionTag string
}

type AliveDialerSetSet map[*AliveDialerSet]int

// NewDialer is for register in general.
func NewDialer(dialer netproxy.Dialer, option *GlobalOption, iOption InstanceOption, property *Property) *Dialer {
	var collections [6]*collection
	for i := range collections {
		collections[i] = newCollection()
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &Dialer{
		GlobalOption:     option,
		InstanceOption:   iOption,
		Dialer:           dialer,
		property:         property,
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
	return nil
}

func (d *Dialer) Property() *Property {
	return d.property
}
