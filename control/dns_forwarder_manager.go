/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"sync"
	"time"

	"github.com/daeuniverse/dae/component/dns"
)

// DnsForwarderManager 管理DNS转发器的生命周期，避免重复创建和资源浪费
type DnsForwarderManager struct {
	// 使用sync.Map存储活跃的转发器
	activeForwarders sync.Map // map[dnsForwarderKey]*forwarderEntry
	
	// 清理goroutine控制
	cleanupInterval time.Duration
	ctx             context.Context
	cancel          context.CancelFunc
}

type forwarderEntry struct {
	forwarder   DnsForwarder
	lastUsed    time.Time
	refCount    int32
	mu          sync.RWMutex
}

// GetForwarder 获取或创建DNS转发器，使用引用计数管理生命周期
func (m *DnsForwarderManager) GetForwarder(upstream *dns.Upstream, dialArg dialArgument) (DnsForwarder, func(), error) {
	key := dnsForwarderKey{upstream: upstream.String(), dialArgument: dialArg}
	
	// 快速路径：尝试获取现有转发器
	if entryValue, ok := m.activeForwarders.Load(key); ok {
		entry := entryValue.(*forwarderEntry)
		entry.mu.Lock()
		entry.refCount++
		entry.lastUsed = time.Now()
		forwarder := entry.forwarder
		entry.mu.Unlock()
		
		// 返回释放函数
		release := func() {
			entry.mu.Lock()
			entry.refCount--
			entry.mu.Unlock()
		}
		
		return forwarder, release, nil
	}
	
	// 慢路径：需要创建新转发器
	newForwarder, err := newDnsForwarder(upstream, dialArg)
	if err != nil {
		return nil, nil, err
	}
	
	entry := &forwarderEntry{
		forwarder: newForwarder,
		lastUsed:  time.Now(),
		refCount:  1,
	}
	
	// 尝试存储，如果已存在则使用现有的
	if existingValue, loaded := m.activeForwarders.LoadOrStore(key, entry); loaded {
		// 有其他goroutine创建了转发器，关闭我们创建的并使用现有的
		newForwarder.Close()
		
		existingEntry := existingValue.(*forwarderEntry)
		existingEntry.mu.Lock()
		existingEntry.refCount++
		existingEntry.lastUsed = time.Now()
		forwarder := existingEntry.forwarder
		existingEntry.mu.Unlock()
		
		release := func() {
			existingEntry.mu.Lock()
			existingEntry.refCount--
			existingEntry.mu.Unlock()
		}
		
		return forwarder, release, nil
	}
	
	// 成功存储新转发器
	release := func() {
		entry.mu.Lock()
		entry.refCount--
		entry.mu.Unlock()
	}
	
	return newForwarder, release, nil
}

// NewDnsForwarderManager 创建新的DNS转发器管理器
func NewDnsForwarderManager() *DnsForwarderManager {
	ctx, cancel := context.WithCancel(context.Background())
	manager := &DnsForwarderManager{
		cleanupInterval: 5 * time.Minute,
		ctx:             ctx,
		cancel:          cancel,
	}
	
	// 启动清理goroutine
	go manager.cleanupLoop()
	
	return manager
}

// cleanupLoop 定期清理未使用的转发器
func (m *DnsForwarderManager) cleanupLoop() {
	ticker := time.NewTicker(m.cleanupInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.cleanup()
		}
	}
}

func (m *DnsForwarderManager) cleanup() {
	now := time.Now()
	cutoff := now.Add(-m.cleanupInterval)
	
	m.activeForwarders.Range(func(key, value interface{}) bool {
		entry := value.(*forwarderEntry)
		entry.mu.RLock()
		shouldDelete := entry.refCount == 0 && entry.lastUsed.Before(cutoff)
		forwarder := entry.forwarder
		entry.mu.RUnlock()
		
		if shouldDelete {
			// 尝试删除并关闭
			if m.activeForwarders.CompareAndDelete(key, value) {
				forwarder.Close()
			}
		}
		
		return true
	})
}

// Shutdown 关闭管理器并清理所有转发器
func (m *DnsForwarderManager) Shutdown() {
	m.cancel()
	
	// 关闭所有活跃的转发器
	m.activeForwarders.Range(func(key, value interface{}) bool {
		entry := value.(*forwarderEntry)
		entry.forwarder.Close()
		return true
	})
}

// 全局DNS转发器管理器实例
var GlobalDnsForwarderManager = NewDnsForwarderManager()
