/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package component

import (
	"context"
	"path"
	"sync"

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
	subscribed := true
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
		subscribed = false
		log.Errorf("Failed to subscribe to link updates: %v", e)
	}

	go mgr.monitor(ch, done, subscribed)
	return mgr
}

// matchingCallbacksLocked collects every registered callback whose pattern
// matches ifName. All of them must run: a single interface can be claimed by
// more than one registration, for example when it matches both the LAN and the
// WAN pattern.
func (m *InterfaceManager) matchingCallbacksLocked(ifName string, pick func(callbackSet) func(netlink.Link)) []func(netlink.Link) {
	var callbacks []func(netlink.Link)
	for _, callback := range m.callbacks {
		matched, err := path.Match(callback.pattern, ifName)
		if err != nil || !matched {
			continue
		}
		if cb := pick(callback); cb != nil {
			callbacks = append(callbacks, cb)
		}
	}
	return callbacks
}

func (m *InterfaceManager) enqueueCallbacks(jobChan chan<- func(), link netlink.Link, callbacks []func(netlink.Link)) {
	if len(callbacks) == 0 {
		return
	}
	select {
	case <-m.closed.Done():
	case jobChan <- func() {
		for _, cb := range callbacks {
			cb(link)
		}
	}:
	}
}

func (m *InterfaceManager) monitor(ch <-chan netlink.LinkUpdate, done chan struct{}, subscribed bool) {
	// A single worker keeps callbacks off the netlink reader while running them
	// in arrival order. Interfaces are not fanned out to per-interface queues:
	// attaching or detaching a datapath is a bounded operation, and a map of
	// per-interface queues and goroutines is never reclaimed, which leaks one
	// goroutine per interface name on hosts that churn through veth devices.
	jobChan := make(chan func(), 128)
	go func() {
		for {
			select {
			case <-m.closed.Done():
				return
			case fn, ok := <-jobChan:
				if !ok {
					return
				}
				fn()
			}
		}
	}()

	for {
		select {
		case <-m.closed.Done():
			close(done)
			close(jobChan)
			// A successful subscription needs a receiver after this loop
			// leaves: closing done makes the library close its netlink socket,
			// but a subscription goroutine already blocked sending an update
			// (link teardown itself bursts RTM_NEWLINK/DELLINK events) never
			// regains one and leaks. The drain ends when the socket close
			// unblocks the sender and the library closes ch. A failed
			// subscription has no sender, so nobody would ever close ch.
			if subscribed {
				go func() {
					for range ch {
					}
				}()
			}
			return
		case update, ok := <-ch:
			if !ok {
				close(done)
				close(jobChan)
				return
			}
			if update.Link == nil {
				m.log.Debug("Ignore netlink update without link")
				continue
			}
			ifName := update.Link.Attrs().Name

			switch update.Header.Type {
			case unix.RTM_NEWLINK:
				m.mu.Lock()
				if _, up := m.upLinks[ifName]; up {
					m.mu.Unlock()
					continue
				}
				m.upLinks[ifName] = true
				callbacks := m.matchingCallbacksLocked(ifName, func(c callbackSet) func(netlink.Link) {
					return c.newCallback
				})
				m.mu.Unlock()
				m.enqueueCallbacks(jobChan, update.Link, callbacks)

			case unix.RTM_DELLINK:
				m.mu.Lock()
				if _, up := m.upLinks[ifName]; !up {
					// The link is already down. Repeated RTM_DELLINK bursts are
					// deduplicated here rather than by a timer, so no callback
					// runs twice for a single down transition.
					m.mu.Unlock()
					continue
				}
				delete(m.upLinks, ifName)
				callbacks := m.matchingCallbacksLocked(ifName, func(c callbackSet) func(netlink.Link) {
					return c.delCallback
				})
				m.mu.Unlock()
				m.enqueueCallbacks(jobChan, update.Link, callbacks)
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
