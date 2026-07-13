/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
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
	// operStates records the last observed operational state per interface so
	// that we can detect a link coming back up after an admin/carrier flap and
	// re-trigger the binding. The kernel removes the ingress qdisc and the
	// attached TC filters when a link goes down, and they are not re-added
	// automatically on re-up, which would silently break traffic steering.
	operStates map[string]netlink.LinkOperState
}

func NewInterfaceManager(log *logrus.Logger) *InterfaceManager {
	closed, toClose := context.WithCancel(context.Background())
	mgr := &InterfaceManager{
		log:        log,
		callbacks:  make([]callbackSet, 0),
		closed:     closed,
		close:      toClose,
		upLinks:    make(map[string]bool),
		operStates: make(map[string]netlink.LinkOperState),
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

func tryEnqueueInterfaceCallback(ctx context.Context, ifQ chan<- func(), fn func()) bool {
	select {
	case <-ctx.Done():
		return false
	case ifQ <- fn:
		return true
	default:
		return false
	}
}

func (m *InterfaceManager) enqueueJob(jobChan chan<- job, j job) {
	select {
	case <-m.closed.Done():
		return
	case jobChan <- j:
	}
}

func (m *InterfaceManager) monitor(ch <-chan netlink.LinkUpdate, done chan struct{}) {
	jobChan := make(chan job, 128)
	go func() {
		// Per-interface queues to preserve order
		queues := make(map[string]chan func())
		timers := make(map[string]*time.Timer)
		stopTimers := func() {
			for _, t := range timers {
				t.Stop()
			}
		}
		defer stopTimers()

		for {
			select {
			case <-m.closed.Done():
				return
			case j, ok := <-jobChan:
				if !ok {
					return
				}
				ifQ, exists := queues[j.ifName]
				if !exists {
					ifQ = make(chan func(), 32)
					queues[j.ifName] = ifQ
					go func(q chan func()) {
						for {
							select {
							case <-m.closed.Done():
								return
							case f, ok := <-q:
								if !ok {
									return
								}
								f()
							}
						}
					}(ifQ)
				}

				// Debounce logic: if a new event for the same interface arrives,
				// reset the timer to delay execution.
				fn := j.fn
				if t, ok := timers[j.ifName]; ok {
					t.Stop()
				}
				ifName := j.ifName
				timers[j.ifName] = time.AfterFunc(200*time.Millisecond, func() {
					if !tryEnqueueInterfaceCallback(m.closed, ifQ, fn) {
						select {
						case <-m.closed.Done():
						default:
							m.log.Warnf("Interface callback queue full for %s, skipping", ifName)
						}
					}
				})
			}
		}
	}()

	for {
		select {
		case <-m.closed.Done():
			close(done)
			close(jobChan)
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
				var jobs []job
				m.mu.Lock()
				newOperState := update.Link.Attrs().OperState
				prevOperState, known := m.operStates[ifName]
				_, exists := m.upLinks[ifName]

				// Re-bind in two situations:
				//   1. The interface is newly seen (first appearance) — the
				//      existing behaviour.
				//   2. The interface was already known but its operational state
				//      transitioned back to Up. The kernel removes the ingress
				//      qdisc and the attached TC filters when a link goes down
				//      (admin down or carrier loss); on re-up they are not
				//      re-added automatically, so without re-binding here the
				//      dataplane silently loses all traffic steering on that
				//      interface until the next full restart.
				rebind := false
				if !exists {
					rebind = true
					m.upLinks[ifName] = true
				} else if known && prevOperState != newOperState && newOperState == netlink.OperUp {
					rebind = true
				}
				m.operStates[ifName] = newOperState
				if !rebind {
					m.mu.Unlock()
					continue
				}
				for _, callback := range m.callbacks {
					matched, err := path.Match(callback.pattern, ifName)
					if err != nil || !matched {
						continue
					}
					if callback.newCallback != nil {
						cb := callback.newCallback
						link := update.Link
						jobs = append(jobs, job{ifName: ifName, fn: func() { cb(link) }})
					}
				}
				m.mu.Unlock()
				for _, j := range jobs {
					m.enqueueJob(jobChan, j)
				}

			case unix.RTM_DELLINK:
				var jobs []job
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
						jobs = append(jobs, job{ifName: ifName, fn: func() { cb(link) }})
					}
				}
				m.mu.Unlock()
				for _, j := range jobs {
					m.enqueueJob(jobChan, j)
				}
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
