/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"fmt"
	"sync"
	"time"
	"unsafe"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/config"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
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

	checkActivated bool
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
	DisableCheck bool
}

type Property struct {
	D.Property
	SubscriptionTag string
}

type AliveDialerSetSet map[*AliveDialerSet]int

func NewGlobalOption(global *config.Global, log *logrus.Logger) *GlobalOption {
	return &GlobalOption{
		ExtraOption: D.ExtraOption{
			AllowInsecure:       global.AllowInsecure,
			TlsImplementation:   global.TlsImplementation,
			UtlsImitate:         global.UtlsImitate,
			BandwidthMaxTx:      global.BandwidthMaxTx,
			BandwidthMaxRx:      global.BandwidthMaxRx,
			TlsFragment:         global.TlsFragment,
			TlsFragmentLength:   global.TlsFragmentLength,
			TlsFragmentInterval: global.TlsFragmentInterval,
		},
		Log:               log,
		TcpCheckOptionRaw: TcpCheckOptionRaw{Raw: global.TcpCheckUrl, Log: log, ResolverNetwork: common.MagicNetwork("udp", global.SoMarkFromDae, global.Mptcp), Method: global.TcpCheckHttpMethod},
		CheckDnsOptionRaw: CheckDnsOptionRaw{Raw: global.UdpCheckDns, ResolverNetwork: common.MagicNetwork("udp", global.SoMarkFromDae, global.Mptcp), Somark: global.SoMarkFromDae},
		CheckInterval:     global.CheckInterval,
		CheckTolerance:    global.CheckTolerance,
		CheckDnsTcp:       true,
	}
}

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
	option.Log.WithField("dialer", d.Property().Name).
		WithField("p", unsafe.Pointer(d)).
		Traceln("NewDialer")
	return d
}

func (d *Dialer) Clone() *Dialer {
	return NewDialer(d.Dialer, d.GlobalOption, d.InstanceOption, d.property)
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
