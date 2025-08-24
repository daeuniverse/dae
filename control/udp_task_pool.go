/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
*/

package control

import (
	"context"
	"sync"
	"time"
)

const (
	UdpTaskQueueLength = 512  // 增加队列容量以支持更高并发
	MaxUdpQueues       = 5000 // 增加最大队列数
	UdpTaskTimeout     = 100 * time.Millisecond // 极短超时时间
)

type UdpTask = func()

// UdpTaskQueue make sure packets with the same key (4 tuples) will be sent in order.
type UdpTaskQueue struct {
	key       string
	p         *UdpTaskPool
	ch        chan UdpTask
	timer     *time.Timer
	agingTime time.Duration
	ctx       context.Context
	closed    chan struct{}
}

func (q *UdpTaskQueue) convoy() {
	defer close(q.closed)
	
	for {
		select {
		case <-q.ctx.Done():
			// 清空剩余任务
			q.drainRemainingTasks()
			return
			
		case task := <-q.ch:
			// 立即异步执行任务，不等待完成
			go q.executeTaskAsync(task)
			
			// 重置老化定时器
			if q.timer != nil {
				q.timer.Reset(q.agingTime)
			}
		}
	}
}

// executeTaskAsync 异步执行单个任务
func (q *UdpTaskQueue) executeTaskAsync(task UdpTask) {
	defer func() {
		if r := recover(); r != nil {
			// 记录panic但不影响其他任务
		}
	}()
	
	if task != nil {
		task()
	}
}

// drainRemainingTasks 清空剩余任务
func (q *UdpTaskQueue) drainRemainingTasks() {
	for {
		select {
		case task := <-q.ch:
			// 异步执行剩余任务
			go q.executeTaskAsync(task)
		default:
			return
		}
	}
}

type UdpTaskPool struct {
	queueChPool sync.Pool
	// 使用RWMutex提高读取性能
	mu sync.RWMutex
	m  map[string]*UdpTaskQueue
}

func NewUdpTaskPool() *UdpTaskPool {
	p := &UdpTaskPool{
		queueChPool: sync.Pool{New: func() any {
			return make(chan UdpTask, UdpTaskQueueLength)
		}},
		mu: sync.RWMutex{},
		m:  map[string]*UdpTaskQueue{},
	}
	return p
}

// EmitTask: Make sure packets with the same key (4 tuples) will be sent in order.
func (p *UdpTaskPool) EmitTask(key string, task UdpTask) {
	if task == nil {
		return
	}

	// 快速健康检查
	if !DefaultUdpHealthMonitor.RegisterConnection() {
		return
	}
	defer DefaultUdpHealthMonitor.UnregisterConnection()

	// 尝试使用读锁快速查找现有队列
	p.mu.RLock()
	q, exists := p.m[key]
	queueCount := len(p.m)
	p.mu.RUnlock()

	if exists {
		// 队列已存在，直接提交任务
		p.submitTaskToQueue(q, task)
		return
	}

	// 需要创建新队列，使用写锁
	p.mu.Lock()
	defer p.mu.Unlock()

	// 双重检查
	if q, exists := p.m[key]; exists {
		p.submitTaskToQueue(q, task)
		return
	}

	// 限制队列数量
	if queueCount >= MaxUdpQueues {
		DefaultUdpHealthMonitor.RecordTimeout()
		return
	}

	// 创建新队列
	ch := p.queueChPool.Get().(chan UdpTask)
	ctx, cancel := context.WithCancel(context.Background())
	q = &UdpTaskQueue{
		key:       key,
		p:         p,
		ch:        ch,
		timer:     nil,
		agingTime: DefaultNatTimeout,
		ctx:       ctx,
		closed:    make(chan struct{}),
	}

	q.timer = time.AfterFunc(q.agingTime, func() {
		p.cleanupQueue(key, q, cancel, ch)
	})

	p.m[key] = q
	go q.convoy()

	// 提交任务到新创建的队列
	p.submitTaskToQueue(q, task)
}

// submitTaskToQueue 提交任务到指定队列（极简版本）
func (p *UdpTaskPool) submitTaskToQueue(q *UdpTaskQueue, task UdpTask) {
	// 包装任务以增加健康监控
	wrappedTask := func() {
		defer func() {
			DefaultUdpHealthMonitor.RecordPacketHandled()
			if r := recover(); r != nil {
				// 记录panic但继续
			}
		}()
		task()
	}

	// 极速任务提交 - 非阻塞模式
	select {
	case q.ch <- wrappedTask:
		// 任务成功排队
	case <-q.ctx.Done():
		// 上下文已取消
		DefaultUdpHealthMonitor.RecordTimeout()
	default:
		// 队列已满，异步重试一次
		go func() {
			select {
			case q.ch <- wrappedTask:
				// 重试成功
			case <-q.ctx.Done():
				DefaultUdpHealthMonitor.RecordTimeout()
			case <-time.After(UdpTaskTimeout):
				DefaultUdpHealthMonitor.RecordTimeout()
			}
		}()
	}
}

// cleanupQueue 清理队列
func (p *UdpTaskPool) cleanupQueue(key string, q *UdpTaskQueue, cancel context.CancelFunc, ch chan UdpTask) {
	p.mu.Lock()
	cancel()
	delete(p.m, key)
	p.mu.Unlock()

	// 等待清理完成，带超时
	select {
	case <-q.closed:
	case <-time.After(1 * time.Second):
		// 强制清理
	}

	// 回收通道
	if len(ch) == 0 {
		for len(ch) > 0 {
			<-ch
		}
		p.queueChPool.Put(ch)
	}
}

var (
	DefaultUdpTaskPool = NewUdpTaskPool()
)
