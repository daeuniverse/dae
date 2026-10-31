/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"sort"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
)

// EbpfAttachmentSnapshot is one tracked TC attachment.
type EbpfAttachmentSnapshot struct {
	Name      string
	Kind      string
	Interface string
	Direction string
	Hook      string
	State     string
}

// MapOccupancySnapshot is one map's occupancy and capacity.
type MapOccupancySnapshot struct {
	Occupancy      *uint64
	Capacity       uint64
	OccupancyKnown bool
}

// EbpfMapsSnapshot is the map section of the datapath detail.
type EbpfMapsSnapshot struct {
	State     string
	ConnState *MapOccupancySnapshot
}

// EbpfSnapshot is the userspace view of the attached eBPF datapath.
type EbpfSnapshot struct {
	Backend            string
	Programs           string
	Hooks              string
	RoutingState       string
	GenerationID       string
	Epoch              string
	Health             string
	LastError          string
	CheckedAt          time.Time
	Attachments        []EbpfAttachmentSnapshot
	ConnStateOccupancy *MapOccupancySnapshot
}

// DatapathSnapshot is the engine-side datapath detail. The HTTP layer maps it
// onto the contract's Datapath schema.
type DatapathSnapshot struct {
	ObservedAt time.Time
	Ebpf       EbpfSnapshot
}

// SnapshotDatapath reports the datapath attachments, routing generation and
// map occupancy of this generation.
func (c *ControlPlane) SnapshotDatapath() DatapathSnapshot {
	return c.snapshotDatapath(true)
}

// SnapshotDatapathSummary is SnapshotDatapath without the batch map scan, for
// the per-poll runtime summary.
func (c *ControlPlane) SnapshotDatapathSummary() DatapathSnapshot {
	return c.snapshotDatapath(false)
}

func (c *ControlPlane) snapshotDatapath(detail bool) DatapathSnapshot {
	now := time.Now()
	snapshot := DatapathSnapshot{
		ObservedAt: now,
		Ebpf: EbpfSnapshot{
			Backend:      "unknown",
			Programs:     "not_loaded",
			Hooks:        "detached",
			RoutingState: "not_published",
			Health:       "unknown",
			CheckedAt:    now,
		},
	}
	if c == nil {
		return snapshot
	}

	snapshot.Ebpf.GenerationID = c.DatapathGenerationID()
	if snapshot.Ebpf.GenerationID != "" {
		snapshot.Ebpf.RoutingState = "published"
	}
	if epoch := c.PolicyEpoch(); epoch != 0 {
		snapshot.Ebpf.Epoch = strconv.FormatUint(uint64(epoch), 10)
	}

	bpf := c.currentBpf()
	if bpf == nil {
		return snapshot
	}
	snapshot.Ebpf.Backend = "real"
	snapshot.Ebpf.Programs = "loaded"
	snapshot.Ebpf.Health = "healthy"
	// Enumerating TC attachments is a cheap in-memory map walk; the batch
	// conn_state scan is what the summary mode avoids.
	snapshot.Ebpf.Attachments = c.tcHookAttachments()
	if detail {
		snapshot.Ebpf.ConnStateOccupancy = connStateOccupancy(bpf)
	}
	if len(snapshot.Ebpf.Attachments) > 0 {
		snapshot.Ebpf.Hooks = "attached"
	} else {
		// A loaded datapath may legitimately have no tracked TC attachments in
		// a userspace-only test; report the truth instead of claiming attached.
		snapshot.Ebpf.Hooks = "unknown"
	}
	return snapshot
}

// tcHookAttachments snapshots the tracked TC hook groups.
func (c *ControlPlane) tcHookAttachments() []EbpfAttachmentSnapshot {
	if c == nil || c.core == nil {
		return nil
	}
	hooks := c.core.tcHooks
	if hooks == nil {
		return nil
	}
	hooks.mu.Lock()
	defer hooks.mu.Unlock()
	attachments := make([]EbpfAttachmentSnapshot, 0, len(hooks.groups))
	for key, group := range hooks.groups {
		if group == nil || len(group.entries) == 0 {
			continue
		}
		var spec tcHookSpec
		for _, entry := range group.entries {
			if entry != nil {
				spec = entry.spec
				break
			}
		}
		attachment := EbpfAttachmentSnapshot{
			Name:  spec.Name,
			State: "attached",
		}
		if attachment.Name == "" && spec.Program != nil {
			attachment.Name = spec.Program.String()
		}
		if key.direction == tcHookIngress {
			attachment.Direction = "ingress"
		} else {
			attachment.Direction = "egress"
		}
		if key.scope == tcHookScopeHost {
			attachment.Kind = "interface"
			attachment.Interface = spec.Ifname
			if attachment.Interface == "" {
				attachment.Interface = strconv.Itoa(key.ifindex)
			}
		} else {
			attachment.Kind = "other"
			attachment.Hook = string(key.scope) + "-netns"
		}
		// The contract requires a non-empty name; fall back to the hook
		// identity when the spec carried no program name.
		if attachment.Name == "" {
			attachment.Name = attachment.Kind + "/" + attachment.Direction
		}
		attachments = append(attachments, attachment)
	}
	sort.Slice(attachments, func(i, j int) bool {
		if attachments[i].Interface != attachments[j].Interface {
			return attachments[i].Interface < attachments[j].Interface
		}
		if attachments[i].Direction != attachments[j].Direction {
			return attachments[i].Direction < attachments[j].Direction
		}
		return attachments[i].Name < attachments[j].Name
	})
	return attachments
}

// connStateOccupancy walks conn_state_map. The map has no O(1) entry count, so
// this is a batch scan; it runs only for an explicit datapath query.
func connStateOccupancy(bpf *bpfObjects) *MapOccupancySnapshot {
	if bpf == nil || bpf.ConnStateMap == nil {
		return nil
	}
	capacity := bpf.ConnStateMap.MaxEntries()
	occupancy := &MapOccupancySnapshot{Capacity: uint64(capacity)}
	if capacity == 0 {
		return occupancy
	}

	keys := make([]bpfTuplesKey, janitorBatchLookupSize)
	values := make([]bpfConnState, janitorBatchLookupSize)
	var cursor ebpf.MapBatchCursor
	var total uint64
	for {
		count, err := bpf.ConnStateMap.BatchLookup(&cursor, keys, values, nil)
		if count > 0 {
			total += uint64(count)
		}
		if err != nil {
			// ErrKeyNotExist is the documented end-of-scan signal even when
			// the batch carried entries. Anything else (closed map, EBADF)
			// interrupted the walk, so the count is partial and must not be
			// reported as authoritative.
			if !stderrors.Is(err, ebpf.ErrKeyNotExist) {
				return occupancy
			}
			break
		}
		if count == 0 {
			break
		}
	}
	occupancy.Occupancy = &total
	occupancy.OccupancyKnown = true
	return occupancy
}
