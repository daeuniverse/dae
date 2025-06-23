/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"sync"
	"time"
)

// SimpleHandlingState 简化的处理状态管理，避免复杂的引用计数
type SimpleHandlingState struct {
	done chan struct{}
	once sync.Once
}

// Wait 等待处理完成
func (s *SimpleHandlingState) Wait() {
	<-s.done
}

// Complete 标记处理完成
func (s *SimpleHandlingState) Complete() {
	s.once.Do(func() {
		close(s.done)
	})
}

// NewSimpleHandlingState 创建新的处理状态
func NewSimpleHandlingState() *SimpleHandlingState {
	return &SimpleHandlingState{
		done: make(chan struct{}),
	}
}

// HandlingStateManager 管理DNS处理状态，避免重复请求
type HandlingStateManager struct {
	states sync.Map // map[string]*SimpleHandlingState
}

// GetOrCreateState 获取或创建处理状态
func (m *HandlingStateManager) GetOrCreateState(key string) (*SimpleHandlingState, bool) {
	// 尝试获取现有状态
	if stateValue, ok := m.states.Load(key); ok {
		return stateValue.(*SimpleHandlingState), false
	}
	
	// 创建新状态
	newState := NewSimpleHandlingState()
	
	// 尝试存储，如果已存在则使用现有的
	if actualValue, loaded := m.states.LoadOrStore(key, newState); loaded {
		return actualValue.(*SimpleHandlingState), false
	}
	
	// 成功创建新状态
	return newState, true
}

// CompleteAndCleanup 完成处理并清理状态
func (m *HandlingStateManager) CompleteAndCleanup(key string, state *SimpleHandlingState) {
	state.Complete()
	
	// 延迟清理，给其他等待的goroutine一些时间
	go func() {
		time.Sleep(100 * time.Millisecond)
		m.states.Delete(key)
	}()
}

// NewHandlingStateManager 创建新的处理状态管理器
func NewHandlingStateManager() *HandlingStateManager {
	return &HandlingStateManager{}
}

// 全局处理状态管理器
var GlobalHandlingStateManager = NewHandlingStateManager()
