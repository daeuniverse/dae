/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package lifecycle

import (
	"sync"
	"time"

	"github.com/daeuniverse/dae/config"
)

// Generation represents a single configuration version with its associated resources.
// It manages three tiers of eBPF resources:
// - Persistent: Survives reloads (routing_tuples_map, udp_conn_state_map)
// - Derived: Rebuilt on config-only reload (routing_map, domain_routing_map)
// - Owned: Rebuilt on full reload (attachment, listener fd, sockhash)
type Generation struct {
	// ID is a unique identifier for this generation (UUID).
	ID string

	// Config is the configuration for this generation.
	Config *config.Config

	// ConfigHash is used to determine if a full reload is needed.
	ConfigHash string

	// Persistent holds state that survives across reloads.
	Persistent *PersistentState

	// Derived holds state that is rebuilt on config changes.
	Derived *DerivedState

	// Owned holds resources that are owned exclusively by this generation.
	Owned *OwnedResources

	// CreatedAt is when this generation was created.
	CreatedAt time.Time

	// ActivatedAt is when this generation became active.
	ActivatedAt time.Time

	mu sync.RWMutex
}

// PersistentState contains eBPF resources that survive reloads.
type PersistentState struct {
	// These maps track connection state across reloads.
	// They are only cleared on explicit shutdown or --clean-shutdown.
	RoutingTuplesMap any // *ebpf.Map
	UDPConnStateMap  any // *ebpf.Map
}

// DerivedState contains eBPF resources that are rebuilt on config changes.
type DerivedState struct {
	// Routing maps are updated when routing rules change.
	RoutingMap       any // *ebpf.Map
	DomainRoutingMap any // *ebpf.Map
	LPMCacheMap      any // *ebpf.Map

	// Userspace matcher is updated atomically during reload.
	RoutingMatcher any // *routing.Matcher

	// DNS cache state is conditionally preserved.
	DNSCache           any  // map[string]*DnsCache
	DNSCacheCompatible bool // True if cache can be reused
}

// OwnedResources contains resources that are owned by this generation.
type OwnedResources struct {
	// BPF program objects.
	BPFObjects any // *bpfObjects

	// Control plane instance for this generation.
	ControlPlane any // *control.ControlPlane

	// Network attachment (TC filters, BPF links, etc.).
	Attachment AttachmentDriver

	// Network namespace.
	NetNS any // *NetworkNamespace

	// Listener file descriptors.
	TProxyListener any // *control.Listener
	DNSListener    any // net.Listener

	// Sockhash for TCP relay offload.
	Sockhash any // *ebpf.Map
}

// IsActive returns true if this generation has been activated.
func (g *Generation) IsActive() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return !g.ActivatedAt.IsZero()
}

// MarkActivated marks this generation as activated at the given time.
func (g *Generation) MarkActivated(t time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.ActivatedAt = t
}

// Close releases all owned resources.
// Persistent and Derived resources are not closed here.
func (g *Generation) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()

	var errs []error

	// Close owned resources in reverse order of acquisition.
	if g.Owned != nil {
		if g.Owned.TProxyListener != nil {
			// Type assertion for closer
			if closer, ok := g.Owned.TProxyListener.(interface{ Close() error }); ok {
				if err := closer.Close(); err != nil {
					errs = append(errs, err)
				}
			}
		}
		if g.Owned.DNSListener != nil {
			if closer, ok := g.Owned.DNSListener.(interface{ Close() error }); ok {
				if err := closer.Close(); err != nil {
					errs = append(errs, err)
				}
			}
		}
		if g.Owned.ControlPlane != nil {
			if closer, ok := g.Owned.ControlPlane.(interface{ Close() error }); ok {
				if err := closer.Close(); err != nil {
					errs = append(errs, err)
				}
			}
		}
		if g.Owned.Attachment != nil {
			if err := g.Owned.Attachment.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		if g.Owned.Sockhash != nil {
			if closer, ok := g.Owned.Sockhash.(interface{ Close() error }); ok {
				if err := closer.Close(); err != nil {
					errs = append(errs, err)
				}
			}
		}
		if g.Owned.BPFObjects != nil {
			if closer, ok := g.Owned.BPFObjects.(interface{ Close() error }); ok {
				if err := closer.Close(); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}

	if len(errs) > 0 {
		return &LifecycleError{
			Op:    "close_generation",
			Phase: string(PhaseRelease),
			ID:    g.ID,
			Cause: joinErrors(errs),
		}
	}
	return nil
}

// NewGeneration creates a new Generation with the given config and hash.
func NewGeneration(id string, cfg *config.Config, hash string) *Generation {
	return &Generation{
		ID:         id,
		Config:     cfg,
		ConfigHash: hash,
		CreatedAt:  time.Now(),
	}
}

// joinErrors combines multiple errors into one.
func joinErrors(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	if len(errs) == 1 {
		return errs[0]
	}
	// Return a composite error
	return &multiError{errors: errs}
}

type multiError struct {
	errors []error
}

func (m *multiError) Error() string {
	msg := "multiple errors:"
	for _, e := range m.errors {
		msg += "\n  - " + e.Error()
	}
	return msg
}
