package dialer

import (
	"context"
	"errors"
	"fmt"
	"github.com/v2rayA/dae/common/consts"
	"github.com/mzz2017/softwind/pkg/fastrand"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/proxy"
	"net"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ConnectivityTestFailedErr = fmt.Errorf("connectivity test failed")
	UnexpectedFieldErr        = fmt.Errorf("unexpected field")
	InvalidParameterErr       = fmt.Errorf("invalid parameters")
)

type Dialer struct {
	proxy.Dialer
	supportUDP bool
	name       string
	protocol   string
	link       string

	Latencies10         *LatenciesN
	aliveDialerSetSetMu sync.Mutex
	// aliveDialerSetSet uses reference counting.
	aliveDialerSetSet map[*AliveDialerSet]int

	tickerMu sync.Mutex
	ticker   *time.Ticker
}

// NewDialer is for register in general.
func NewDialer(dialer proxy.Dialer, supportUDP bool, name string, protocol string, link string) *Dialer {
	d := newDialer(dialer, supportUDP, name, protocol, link)
	go d.aliveBackground()
	return d
}

// newDialer does not run background tasks.
func newDialer(dialer proxy.Dialer, supportUDP bool, name string, protocol string, link string) *Dialer {
	d := &Dialer{
		Dialer:      dialer,
		supportUDP:  supportUDP,
		name:        name,
		protocol:    protocol,
		link:        link,
		Latencies10: NewLatenciesN(10),
		// Set a very big cycle to wait for init.
		ticker:            time.NewTicker(time.Hour),
		aliveDialerSetSet: make(map[*AliveDialerSet]int),
	}
	return d
}

func (d *Dialer) aliveBackground() {
	timeout := 10 * time.Second
	cycle := 15 * time.Second
	// Test once immediately.
	go d.Test(timeout, consts.TestUrl)

	// Sleep to avoid avalanche.
	time.Sleep(time.Duration(fastrand.Int63n(int64(cycle))))
	d.tickerMu.Lock()
	d.ticker.Reset(cycle)
	d.tickerMu.Unlock()
	for range d.ticker.C {
		// No need to test if there is no dialer selection policy using its latency.
		if len(d.aliveDialerSetSet) > 0 {
			d.Test(timeout, consts.TestUrl)
		}
	}
}

func (d *Dialer) Close() error {
	d.tickerMu.Lock()
	d.ticker.Stop()
	d.tickerMu.Unlock()
	return nil
}

// RegisterAliveDialerSet is thread-safe.
func (d *Dialer) RegisterAliveDialerSet(a *AliveDialerSet) {
	d.aliveDialerSetSetMu.Lock()
	d.aliveDialerSetSet[a]++
	d.aliveDialerSetSetMu.Unlock()
}

// UnregisterAliveDialerSet is thread-safe.
func (d *Dialer) UnregisterAliveDialerSet(a *AliveDialerSet) {
	d.aliveDialerSetSetMu.Lock()
	defer d.aliveDialerSetSetMu.Unlock()
	d.aliveDialerSetSet[a]--
	if d.aliveDialerSetSet[a] <= 0 {
		delete(d.aliveDialerSetSet, a)
	}
}

func (d *Dialer) SupportUDP() bool {
	return d.supportUDP
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

func (d *Dialer) Test(timeout time.Duration, url string) (ok bool, err error) {
	ctx, cancel := context.WithTimeout(context.TODO(), timeout)
	defer cancel()
	start := time.Now()
	// Calc latency.
	defer func() {
		var alive bool
		if ok && err == nil {
			// No error.
			latency := time.Since(start)
			// FIXME: Use log instead of logrus.
			logrus.Debugf("Connectivity Test: %v: %v", d.name, latency)
			d.Latencies10.AppendLatency(latency)
			alive = true
		} else {
			// Append timeout if there is any error or unexpected status code.
			if err != nil {
				logrus.Debugf("Test [%v]: %v", d.name, err.Error())
			}
			d.Latencies10.AppendLatency(timeout)
		}
		// Inform DialerGroups to update state.
		d.aliveDialerSetSetMu.Lock()
		for a := range d.aliveDialerSetSet {
			a.SetAlive(d, alive)
		}
		d.aliveDialerSetSetMu.Unlock()
	}()

	// HTTP(S) test.
	cd := ContextDialer{d.Dialer}
	cli := http.Client{
		Transport: &http.Transport{
			DialContext: cd.DialContext,
		},
		Timeout: timeout,
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, fmt.Errorf("%v: %w", ConnectivityTestFailedErr, err)
	}
	resp, err := cli.Do(req)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr); netErr.Timeout() {
			err = fmt.Errorf("timeout")
		}
		return false, fmt.Errorf("%v: %w", ConnectivityTestFailedErr, err)
	}
	defer resp.Body.Close()
	// Judge the status code.
	if page := path.Base(req.URL.Path); strings.HasPrefix(page, "generate_") {
		return strconv.Itoa(resp.StatusCode) == strings.TrimPrefix(page, "generate_"), nil
	}
	return resp.StatusCode >= 200 && resp.StatusCode < 400, nil
}
