/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"strconv"
	"time"
)

// FlowHistoryCapacity bounds the retained closed-flow history.
const FlowHistoryCapacity = 2048

// FlowHistoryRetention bounds the age of a retained closed flow.
const FlowHistoryRetention = 15 * time.Minute

// SessionFlowSnapshot is one live or finished userspace flow.
type SessionFlowSnapshot struct {
	ID            string
	Network       string
	Src           netip.AddrPort
	Dst           netip.AddrPort
	Outbound      string
	DialerName    string
	DialerLink    string
	Domain        string
	Pname         string
	Pid           uint32
	Dscp          uint32
	Mark          uint32
	StartedAt     time.Time
	UploadBytes   uint64
	DownloadBytes uint64
	HasBytes      bool
}

// SessionFlowHistoryEntry is one finished flow.
type SessionFlowHistoryEntry struct {
	SessionFlowSnapshot
	Revision uint64
	EndedAt  time.Time
	State    string
}

func flowIDOf(network string, src, dst netip.AddrPort, started time.Time) string {
	sum := sha256.Sum256([]byte(network + "\x00" + src.String() + "\x00" + dst.String() + "\x00" + strconv.FormatInt(started.UnixNano(), 10)))
	return "f_" + hex.EncodeToString(sum[:8])
}

func (f *FlowRuntime) snapshot() SessionFlowSnapshot {
	if f == nil {
		return SessionFlowSnapshot{}
	}
	snapshot := SessionFlowSnapshot{
		ID:            f.id,
		Network:       f.network,
		Src:           f.src,
		Dst:           f.dst,
		Domain:        f.binding.Egress.SniffedDomain,
		Pname:         f.pname,
		Pid:           f.pid,
		Dscp:          f.dscp,
		Mark:          f.mark,
		StartedAt:     f.startedAt,
		UploadBytes:   f.uploadBytes.Load(),
		DownloadBytes: f.downloadBytes.Load(),
		HasBytes:      true,
	}
	if group := f.binding.Egress.Outbound; group != nil {
		snapshot.Outbound = group.Name
	}
	if dialer := f.binding.Egress.Dialer; dialer != nil {
		if property := dialer.Property(); property != nil {
			snapshot.DialerName = property.Name
			snapshot.DialerLink = property.Link
		}
	}
	return snapshot
}

func (f *UDPFlowRuntime) snapshot() SessionFlowSnapshot {
	if f == nil {
		return SessionFlowSnapshot{}
	}
	snapshot := SessionFlowSnapshot{
		ID:        f.id,
		Network:   "udp",
		Src:       f.src,
		Dst:       f.dst,
		Mark:      f.binding.Route.Mark,
		StartedAt: f.startedAt,
	}
	if f.endpoint != nil {
		snapshot.Domain = f.endpoint.SniffedDomain
		if f.endpoint.Outbound != nil {
			snapshot.Outbound = f.endpoint.Outbound.Name
		}
		if f.endpoint.Dialer != nil {
			if property := f.endpoint.Dialer.Property(); property != nil {
				snapshot.DialerName = property.Name
				snapshot.DialerLink = property.Link
			}
		}
	}
	if snapshot.Outbound == "" && f.binding.Egress.Outbound != nil {
		snapshot.Outbound = f.binding.Egress.Outbound.Name
	}
	return snapshot
}

// SetFlowRoutingMeta records the kernel routing evidence on a live TCP flow.
func (f *FlowRuntime) SetFlowRoutingMeta(routingResult *bpfRoutingResult) {
	if f == nil || routingResult == nil {
		return
	}
	f.pname = ProcessName2String(routingResult.Pname[:])
	f.pid = routingResult.Pid
	f.dscp = uint32(routingResult.Dscp)
	f.mark = routingResult.Mark
}

// ActiveFlowSnapshots returns every live userspace flow.
func (m *SessionManager) ActiveFlowSnapshots() []SessionFlowSnapshot {
	if m == nil {
		return nil
	}
	flows := make([]SessionFlowSnapshot, 0, m.tcpCount.Load()+m.udpCount.Load())
	m.flows.Range(func(_, value any) bool {
		if flow, ok := value.(*FlowRuntime); ok {
			flows = append(flows, flow.snapshot())
		}
		return true
	})
	m.udpFlows.Range(func(_, value any) bool {
		if flow, ok := value.(*UDPFlowRuntime); ok {
			flows = append(flows, flow.snapshot())
		}
		return true
	})
	return flows
}

// CloseFlowByID cancels one live flow. It reports whether the flow existed.
func (m *SessionManager) CloseFlowByID(id string) bool {
	if m == nil || id == "" {
		return false
	}
	var target *FlowRuntime
	m.flows.Range(func(_, value any) bool {
		if flow, ok := value.(*FlowRuntime); ok && flow.id == id {
			target = flow
			return false
		}
		return true
	})
	if target != nil {
		_ = target.abort()
		return true
	}
	var udpTarget *UDPFlowRuntime
	m.udpFlows.Range(func(_, value any) bool {
		if flow, ok := value.(*UDPFlowRuntime); ok && flow.id == id {
			udpTarget = flow
			return false
		}
		return true
	})
	if udpTarget != nil {
		_ = udpTarget.abort()
		return true
	}
	return false
}

func (m *SessionManager) appendFlowHistory(flow SessionFlowSnapshot, endedAt time.Time) {
	if m == nil || flow.ID == "" {
		return
	}
	m.flowHistoryMu.Lock()
	defer m.flowHistoryMu.Unlock()
	m.pruneFlowHistoryLocked(endedAt)
	m.flowHistoryRevision++
	if m.flowHistory == nil {
		m.flowHistory = make([]SessionFlowHistoryEntry, FlowHistoryCapacity)
	}
	entry := SessionFlowHistoryEntry{SessionFlowSnapshot: flow, Revision: m.flowHistoryRevision, EndedAt: endedAt, State: "closed"}
	if m.flowHistoryLen < len(m.flowHistory) {
		index := (m.flowHistoryStart + m.flowHistoryLen) % len(m.flowHistory)
		m.flowHistory[index] = entry
		m.flowHistoryLen++
		return
	}
	m.flowHistory[m.flowHistoryStart] = entry
	m.flowHistoryStart = (m.flowHistoryStart + 1) % len(m.flowHistory)
}

// FlowHistorySnapshots returns finished flows, oldest first, with revisions.
func (m *SessionManager) FlowHistorySnapshots() ([]SessionFlowHistoryEntry, uint64) {
	if m == nil {
		return nil, 0
	}
	m.flowHistoryMu.Lock()
	defer m.flowHistoryMu.Unlock()
	now := time.Now()
	m.pruneFlowHistoryLocked(now)
	entries := make([]SessionFlowHistoryEntry, 0, m.flowHistoryLen)
	for i := 0; i < m.flowHistoryLen; i++ {
		entries = append(entries, m.flowHistory[(m.flowHistoryStart+i)%len(m.flowHistory)])
	}
	return entries, m.flowHistoryRevision
}

func (m *SessionManager) pruneFlowHistoryLocked(now time.Time) {
	cutoff := now.Add(-FlowHistoryRetention)
	for m.flowHistoryLen > 0 {
		oldest := m.flowHistory[m.flowHistoryStart]
		if !oldest.EndedAt.Before(cutoff) {
			break
		}
		m.flowHistoryStart = (m.flowHistoryStart + 1) % len(m.flowHistory)
		m.flowHistoryLen--
	}
}

// FlowHistoryEntryByID finds one retained finished flow.
func (m *SessionManager) FlowHistoryEntryByID(id string) (SessionFlowHistoryEntry, bool) {
	entries, _ := m.FlowHistorySnapshots()
	for _, entry := range entries {
		if entry.ID == id {
			return entry, true
		}
	}
	return SessionFlowHistoryEntry{}, false
}

func (c *ControlPlane) activeSessionManager() *SessionManager {
	if c == nil {
		return nil
	}
	manager, _ := c.controlPlaneSessionManager()
	return manager
}

// ActiveFlowSnapshots returns the live flows of this generation's process
// session manager.
func (c *ControlPlane) ActiveFlowSnapshots() []SessionFlowSnapshot {
	return c.activeSessionManager().ActiveFlowSnapshots()
}

// CloseFlowByID cancels one live flow of the process session manager.
func (c *ControlPlane) CloseFlowByID(id string) bool {
	return c.activeSessionManager().CloseFlowByID(id)
}

// FlowHistory returns finished flows retained by the process session manager.
func (c *ControlPlane) FlowHistory() ([]SessionFlowHistoryEntry, uint64) {
	return c.activeSessionManager().FlowHistorySnapshots()
}

// FlowHistoryByID finds one retained finished flow.
func (c *ControlPlane) FlowHistoryByID(id string) (SessionFlowHistoryEntry, bool) {
	return c.activeSessionManager().FlowHistoryEntryByID(id)
}
