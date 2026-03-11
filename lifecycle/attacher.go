/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package lifecycle

import (
	"fmt"

	"github.com/sirupsen/logrus"
	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
)

// AttachmentDriver is the interface for eBPF program attachment.
// Different implementations support TCX (kernel >= 6.6) and Legacy TC.
type AttachmentDriver interface {
	// Attach attaches the given BPF programs to the specified interfaces.
	Attach(programs any, ifaces []string) error

	// Update atomically updates the attached programs (TCX only).
	// Returns an error if not supported by this driver.
	Update(programs any) error

	// Detach removes the BPF programs from interfaces.
	Detach() error

	// Close releases resources held by the driver.
	Close() error

	// Type returns the attachment type for logging/metrics.
	Type() AttachmentType
}

// AttachmentType indicates the attachment mechanism being used.
type AttachmentType string

const (
	AttachmentTypeTCX       AttachmentType = "tcx"        // TCX/BPF link (kernel >= 6.6)
	AttachmentTypeLegacyTC  AttachmentType = "legacy_tc"  // Legacy TC filter
)

// AttachmentConfig holds configuration for attachment.
type AttachmentConfig struct {
	Log          *logrus.Logger
	KernelVersion *internal.Version
	Interfaces   []string // WAN and LAN interfaces
	Flip         int      // Flip value for handle management
}

// NewAttachmentDriver creates an appropriate attachment driver based on kernel version.
// It tries TCX first (kernel >= 6.6) and falls back to Legacy TC.
func NewAttachmentDriver(cfg *AttachmentConfig) (AttachmentDriver, error) {
	// Try TCX first if kernel version supports it
	// Kernel version code for 6.6.0 is 0x060600 = 394752
	if cfg.KernelVersion != nil && !cfg.KernelVersion.Unspecified() && cfg.KernelVersion.Kernel() >= 0x060600 {
		tcx := &AttachmentDriverTCX{
			cfg:   cfg,
			links: make(map[string]any),
		}
		return tcx, nil
	}

	// Fall back to Legacy TC
	legacy := &AttachmentDriverLegacyTC{
		cfg:     cfg,
		filters: make(map[string]*tcFilter),
	}
	return legacy, nil
}

// AttachmentDriverTCX implements TCX/BPF link attachment for kernel >= 6.6.
// This supports seamless program updates via bpf_link__update_program.
type AttachmentDriverTCX struct {
	cfg    *AttachmentConfig
	links  map[string]any // ifname -> link (ebpf.Link)
	prog   any            // Current program
	closed bool
}

// Attach attaches BPF programs using TCX/BPF links.
func (d *AttachmentDriverTCX) Attach(programs any, ifaces []string) error {
	// Implementation would use bpf_link_create for TCX
	// For now, this is a placeholder that demonstrates the interface
	d.cfg.Log.Debugf("[TCX] Attaching to interfaces: %v", ifaces)
	d.prog = programs
	return nil
}

// Update atomically updates the attached program using bpf_link__update_program.
// This is the key advantage of TCX - no detach/recreate window.
func (d *AttachmentDriverTCX) Update(programs any) error {
	if d.closed {
		return fmt.Errorf("driver is closed")
	}
	d.cfg.Log.Debug("[TCX] Updating programs atomically")
	// Implementation would use bpf_link_update_program
	d.prog = programs
	return nil
}

// Detach removes the BPF links.
func (d *AttachmentDriverTCX) Detach() error {
	for ifname, link := range d.links {
		if closer, ok := link.(interface{ Close() error }); ok {
			if err := closer.Close(); err != nil {
				d.cfg.Log.Warnf("[TCX] Failed to detach from %s: %v", ifname, err)
			}
		}
		delete(d.links, ifname)
	}
	return nil
}

// Close releases all resources.
func (d *AttachmentDriverTCX) Close() error {
	d.closed = true
	return d.Detach()
}

// Type returns the attachment type.
func (d *AttachmentDriverTCX) Type() AttachmentType {
	return AttachmentTypeTCX
}

// AttachmentDriverLegacyTC implements Legacy TC filter attachment.
// This uses handle flipping for reloads.
type AttachmentDriverLegacyTC struct {
	cfg     *AttachmentConfig
	filters map[string]*tcFilter
	prog    any
	closed  bool
}

// tcFilter represents a TC filter attachment.
type tcFilter struct {
	iface    string
	parent   uint32
	handle   uint32
	priority uint32
	ingress  bool
	l2       bool
	fd       int
	name     string
}

// Attach attaches BPF programs using Legacy TC filters.
func (d *AttachmentDriverLegacyTC) Attach(programs any, ifaces []string) error {
	d.cfg.Log.Debugf("[LegacyTC] Attaching to interfaces: %v", ifaces)
	d.prog = programs
	return nil
}

// Update is not supported for Legacy TC - returns error.
func (d *AttachmentDriverLegacyTC) Update(programs any) error {
	return fmt.Errorf("atomic update not supported for Legacy TC; use full reload")
}

// Detach removes TC filters.
func (d *AttachmentDriverLegacyTC) Detach() error {
	for _, f := range d.filters {
		// Implementation would use netlink.FilterDel
		d.cfg.Log.Debugf("[LegacyTC] Detaching filter %s from %s", f.name, f.iface)
	}
	d.filters = make(map[string]*tcFilter)
	return nil
}

// Close releases all resources.
func (d *AttachmentDriverLegacyTC) Close() error {
	d.closed = true
	return d.Detach()
}

// Type returns the attachment type.
func (d *AttachmentDriverLegacyTC) Type() AttachmentType {
	return AttachmentTypeLegacyTC
}

// SupportsUpdate returns true if the driver supports atomic program updates.
func SupportsUpdate(driver AttachmentDriver) bool {
	_, ok := driver.(*AttachmentDriverTCX)
	return ok
}
