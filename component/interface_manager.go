/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package component

import (
	"context"
	"path"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type callbackSet struct {
	pattern     string
	newCallback func(netlink.Link)
	delCallback func(netlink.Link)
}

type InterfaceManager struct {
	log       *logrus.Logger
	closed    context.Context
	close     context.CancelFunc
	mu        sync.Mutex
	callbacks []callbackSet
	upLinks   map[string]bool
}

func NewInterfaceManager(log *logrus.Logger) *InterfaceManager {
	closed, toClose := context.WithCancel(context.Background())
	mgr := &InterfaceManager{
		log:       log,
		callbacks: make([]callbackSet, 0),
		closed:    closed,
		close:     toClose,
		upLinks:   make(map[string]bool),
	}

	ch := make(chan netlink.LinkUpdate)
	done := make(chan struct{})
	if e := netlink.LinkSubscribeWithOptions(ch, done, netlink.LinkSubscribeOptions{
		ErrorCallback: func(err error) {
			select {
			case <-closed.Done():
				return
			default:
				log.Debug("LinkSubscribe:", err)
			}
		},
		ListExisting: true,
	}); e != nil {
		log.Errorf("Failed to subscribe to link updates: %v", e)
	}

	go mgr.monitor(ch, done)
	return mgr
}

type job struct {
	ifName string
	fn     func()
}

func (m *InterfaceManager) monitor(ch <-chan netlink.LinkUpdate, done chan struct{}) {
	jobChan := make(chan job, 128)
	go func() {
		// Per-interface queues to preserve order
		queues := make(map[string]chan func())
		timers := make(map[string]*time.Timer)
		for j := range jobChan {
			ifQ, ok := queues[j.ifName]
			if !ok {
				ifQ = make(chan func(), 32)
				queues[j.ifName] = ifQ
				go func(ifName string, q chan func()) {
					for f := range q {
						f()
					}
				}(j.ifName, ifQ)
			}

			// Debounce logic: if a new event for the same interface arrives,
			// reset the timer to delay execution.
			fn := j.fn
			if t, ok := timers[j.ifName]; ok {
				t.Stop()
			}
			timers[j.ifName] = time.AfterFunc(200*time.Millisecond, func() {
				select {
				case ifQ <- fn:
				default:
					m.log.Warnf("Interface callback queue full for %s, skipping", j.ifName)
				}
			})
		}
		for _, q := range queues {
			close(q)
		}
		for _, t := range timers {
			t.Stop()
		}
	}()

	for {
		select {
		case <-m.closed.Done():
			close(done)
			close(jobChan)
			return
		case update := <-ch:
			ifName := update.Link.Attrs().Name

			switch update.Header.Type {
			case unix.RTM_NEWLINK:
				m.mu.Lock()
				_, exists := m.upLinks[ifName]
				if exists {
					m.mu.Unlock()
					continue
				}
				m.upLinks[ifName] = true
				for _, callback := range m.callbacks {
					matched, err := path.Match(callback.pattern, ifName)
					if err != nil || !matched {
						continue
					}
					if callback.newCallback != nil {
						cb := callback.newCallback
						link := update.Link
						jobChan <- job{ifName: ifName, fn: func() { cb(link) }}
					}
				}
				m.mu.Unlock()

			case unix.RTM_DELLINK:
				m.mu.Lock()
				delete(m.upLinks, ifName)
				for _, callback := range m.callbacks {
					matched, err := path.Match(callback.pattern, ifName)
					if err != nil || !matched {
						continue
					}
					if callback.delCallback != nil {
						cb := callback.delCallback
						link := update.Link
						jobChan <- job{ifName: ifName, fn: func() { cb(link) }}
					}
				}
				m.mu.Unlock()
			}
		}
	}
}

func (m *InterfaceManager) RegisterWithPattern(pattern string, initCallback func(netlink.Link), newCallback func(netlink.Link), delCallback func(netlink.Link)) {
	m.mu.Lock()
	defer m.mu.Unlock()

	links, err := netlink.LinkList()
	if err == nil {
		for _, link := range links {
			ifName := link.Attrs().Name
			if matched, err := path.Match(pattern, ifName); err == nil && matched {
				m.upLinks[ifName] = true

				if initCallback != nil {
					link := link
					go initCallback(link)
				}
			}
		}
	} else {
		m.log.Errorf("Failed to get link list: %v", err)
	}

	m.callbacks = append(m.callbacks, callbackSet{
		pattern:     pattern,
		newCallback: newCallback,
		delCallback: delCallback,
	})
}

func (m *InterfaceManager) Register(ifname string, initCallback func(netlink.Link), newCallback func(netlink.Link), delCallback func(netlink.Link)) {
	m.mu.Lock()
	defer m.mu.Unlock()

	link, err := netlink.LinkByName(ifname)
	if err == nil {
		m.upLinks[ifname] = true

		if initCallback != nil {
			go initCallback(link)
		}
	}

	m.callbacks = append(m.callbacks, callbackSet{
		pattern:     ifname,
		newCallback: newCallback,
		delCallback: delCallback,
	})
}

// Close cancels the context to stop the monitor goroutine
func (m *InterfaceManager) Close() error {
	m.close()
	return nil
}
