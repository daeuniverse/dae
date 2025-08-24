/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// UdpHealthMonitor monitors UDP processing health and prevents deadlocks
type UdpHealthMonitor struct {
	// 基本指标
	activeConnections    int64
	totalPacketsHandled  int64
	droppedPackets      int64
	timeoutOccurrences  int64
	
	// 控制参数
	isShuttingDown      int32
	maxActiveConns      int64
	healthCheckInterval time.Duration
	
	// 监控
	lastActivity        time.Time
	mu                 sync.RWMutex
	ctx                context.Context
	cancel             context.CancelFunc
}

// NewUdpHealthMonitor creates a new UDP health monitor
func NewUdpHealthMonitor() *UdpHealthMonitor {
	ctx, cancel := context.WithCancel(context.Background())
	monitor := &UdpHealthMonitor{
		maxActiveConns:      20000, // 增加最大连接数
		healthCheckInterval: 30 * time.Second,
		lastActivity:        time.Now(),
		ctx:                 ctx,
		cancel:              cancel,
	}
	
	go monitor.healthCheckLoop()
	return monitor
}

// healthCheckLoop runs periodic health checks
func (m *UdpHealthMonitor) healthCheckLoop() {
	ticker := time.NewTicker(m.healthCheckInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.performHealthCheck()
		}
	}
}

// performHealthCheck 执行简化的健康检查
func (m *UdpHealthMonitor) performHealthCheck() {
	activeConns := atomic.LoadInt64(&m.activeConnections)
	totalPackets := atomic.LoadInt64(&m.totalPacketsHandled)
	droppedPackets := atomic.LoadInt64(&m.droppedPackets)
	timeouts := atomic.LoadInt64(&m.timeoutOccurrences)
	
	// 简单的日志记录（如果需要的话）
	_ = activeConns
	_ = totalPackets
	_ = droppedPackets
	_ = timeouts
	
	// 重置计数器防止溢出
	if totalPackets > 10000000 { // 1000万包后重置
		atomic.StoreInt64(&m.totalPacketsHandled, 0)
		atomic.StoreInt64(&m.droppedPackets, 0)
		atomic.StoreInt64(&m.timeoutOccurrences, 0)
	}
}

// RegisterConnection registers a new UDP connection
func (m *UdpHealthMonitor) RegisterConnection() bool {
	if atomic.LoadInt32(&m.isShuttingDown) != 0 {
		return false
	}
	
	activeConns := atomic.AddInt64(&m.activeConnections, 1)
	if activeConns > m.maxActiveConns {
		atomic.AddInt64(&m.activeConnections, -1)
		atomic.AddInt64(&m.droppedPackets, 1)
		return false
	}
	
	m.mu.Lock()
	m.lastActivity = time.Now()
	m.mu.Unlock()
	
	return true
}

// UnregisterConnection unregisters a UDP connection
func (m *UdpHealthMonitor) UnregisterConnection() {
	atomic.AddInt64(&m.activeConnections, -1)
}

// RecordPacketHandled records a successfully handled packet
func (m *UdpHealthMonitor) RecordPacketHandled() {
	atomic.AddInt64(&m.totalPacketsHandled, 1)
	
	m.mu.Lock()
	m.lastActivity = time.Now()
	m.mu.Unlock()
}

// RecordTimeout records a timeout occurrence
func (m *UdpHealthMonitor) RecordTimeout() {
	atomic.AddInt64(&m.timeoutOccurrences, 1)
}

// IsHealthy returns true if the system is in a healthy state
func (m *UdpHealthMonitor) IsHealthy() bool {
	activeConns := atomic.LoadInt64(&m.activeConnections)
	timeouts := atomic.LoadInt64(&m.timeoutOccurrences)
	totalPackets := atomic.LoadInt64(&m.totalPacketsHandled)
	
	// 基本健康检查
	if activeConns > m.maxActiveConns*9/10 { // 90% 容量
		return false
	}
	
	// 超时率检查
	if totalPackets > 1000 {
		timeoutRate := float64(timeouts) / float64(totalPackets)
		if timeoutRate > 0.05 { // 5% 超时率阈值
			return false
		}
	}
	
	return true
}

// Shutdown shuts down the health monitor
func (m *UdpHealthMonitor) Shutdown() {
	atomic.StoreInt32(&m.isShuttingDown, 1)
	m.cancel()
}

// GetStats returns current statistics
func (m *UdpHealthMonitor) GetStats() map[string]int64 {
	return map[string]int64{
		"active_connections":    atomic.LoadInt64(&m.activeConnections),
		"total_packets_handled": atomic.LoadInt64(&m.totalPacketsHandled),
		"dropped_packets":       atomic.LoadInt64(&m.droppedPackets),
		"timeout_occurrences":   atomic.LoadInt64(&m.timeoutOccurrences),
		"max_active_conns":      m.maxActiveConns,
	}
}

// Global UDP health monitor instance
var DefaultUdpHealthMonitor = NewUdpHealthMonitor()
