package control

import (
	"sync"
	"time"
)

const UdpTaskQueueLength = 128

type UdpTask = func()

type UdpTaskQueue struct {
	key       string
	ch        chan UdpTask
	timer     *time.Timer
	agingTime time.Duration
	closed    chan struct{}
	freed     chan struct{}
}

func (q *UdpTaskQueue) Push(task UdpTask) {
	q.timer.Reset(q.agingTime)
	q.ch <- task
}

type UdpTaskPool struct {
	queueChPool sync.Pool
	// mu protects m
	mu sync.Mutex
	m  map[string]*UdpTaskQueue
}

func NewUdpTaskPool() *UdpTaskPool {
	p := &UdpTaskPool{
		queueChPool: sync.Pool{New: func() any {
			return make(chan UdpTask, UdpTaskQueueLength)
		}},
		mu: sync.Mutex{},
		m:  map[string]*UdpTaskQueue{},
	}
	return p
}

func (p *UdpTaskPool) convoy(q *UdpTaskQueue) {
	for {
		select {
		case <-q.closed:
		clearloop:
			for {
				select {
				case t := <-q.ch:
					// Emit it back due to closed q.
					p.EmitTask(q.key, t)
				default:
					break clearloop
				}
			}
			close(q.freed)
			return
		case t := <-q.ch:
			t()
		}
	}
}

func (p *UdpTaskPool) EmitTask(key string, task UdpTask) {
	p.mu.Lock()
	q, ok := p.m[key]
	if !ok {
		ch := p.queueChPool.Get().(chan UdpTask)
		q = &UdpTaskQueue{
			key:       key,
			ch:        ch,
			timer:     nil,
			agingTime: DefaultNatTimeout,
			closed:    make(chan struct{}),
			freed:     make(chan struct{}),
		}
		q.timer = time.AfterFunc(q.agingTime, func() {
			// This func may be invoked twice due to concurrent Reset.
			select {
			case <-q.closed:
				return
			default:
			}
			p.mu.Lock()
			defer p.mu.Unlock()
			if p.m[key] == q {
				delete(p.m, key)
			}
			close(q.closed)
			<-q.freed
			p.queueChPool.Put(ch)
		})
		p.m[key] = q
		go p.convoy(q)
	}
	p.mu.Unlock()
	q.Push(task)
}

var DefaultUdpTaskPool = NewUdpTaskPool()
