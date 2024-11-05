package control

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/panjf2000/ants"
)

var isTest = false

const UdpTaskQueueLength = 128

type UdpTask = func()

// UdpTaskQueue make sure packets with the same key (4 tuples) will be sent in order.
type UdpTaskQueue struct {
	key       string
	p         *UdpTaskPool
	ch        chan UdpTask
	timer     *time.Timer
	agingTime time.Duration
	closed    atomic.Bool
	freed     chan struct{}
}

func (q *UdpTaskQueue) Push(task UdpTask) {
	q.timer.Reset(q.agingTime)
	q.ch <- task
}

func (q *UdpTaskQueue) convoy() {
	for {
		if q.closed.Load() {
		clearloop:
			for {
				select {
				case t := <-q.ch:
					// Emit it back due to closed q.
					ReemitWorkers.Submit(func() {
						q.p.EmitTask(q.key, t)
					})
				default:
					break clearloop
				}
			}
			close(q.freed)
			return
		} else {
			t := <-q.ch
			t()
		}
	}
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

// EmitTask: Make sure packets with the same key (4 tuples) will be sent in order.
func (p *UdpTaskPool) EmitTask(key string, task UdpTask) {
	p.mu.Lock()
	q, ok := p.m[key]
	if !ok {
		ch := p.queueChPool.Get().(chan UdpTask)
		q = &UdpTaskQueue{
			key:       key,
			p:         p,
			ch:        ch,
			timer:     nil,
			agingTime: DefaultNatTimeout,
			closed:    atomic.Bool{},
			freed:     make(chan struct{}),
		}
		q.timer = time.AfterFunc(q.agingTime, func() {
			// This func may be invoked twice due to concurrent Reset.
			if !q.closed.CompareAndSwap(false, true) {
				return
			}
			if isTest {
				time.Sleep(3 * time.Microsecond)
			}
			p.mu.Lock()
			defer p.mu.Unlock()
			if p.m[key] == q {
				delete(p.m, key)
			}
			// Trigger next loop in func convoy
			q.ch <- func() {}
			<-q.freed
			p.queueChPool.Put(ch)
		})
		p.m[key] = q
		go q.convoy()
	}
	p.mu.Unlock()
	q.Push(task)
}

var (
	DefaultUdpTaskPool = NewUdpTaskPool()
	ReemitWorkers      *ants.Pool
)

func init() {
	var err error
	ReemitWorkers, err = ants.NewPool(UdpTaskQueueLength/2, ants.WithExpiryDuration(AnyfromTimeout))
	if err != nil {
		panic(err)
	}
}
