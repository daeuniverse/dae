/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package lifecycle

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/okzk/sdnotify"
	"github.com/sirupsen/logrus"
)

// SystemdNotifier handles systemd notify protocol communication.
// Supports Type=notify and Type=notify-reload service modes.
type SystemdNotifier struct {
	log       *logrus.Logger
	enabled   bool
	mu        sync.Mutex
	startTime time.Time
}

// NewSystemdNotifier creates a new SystemdNotifier.
// It auto-detects if running under systemd by checking NOTIFY_SOCKET.
func NewSystemdNotifier(log *logrus.Logger) *SystemdNotifier {
	enabled := os.Getenv("NOTIFY_SOCKET") != ""
	if enabled {
		log.Debug("systemd notify socket detected")
	}
	return &SystemdNotifier{
		log:       log,
		enabled:   enabled,
		startTime: time.Now(),
	}
}

// Enabled returns true if systemd notifications are enabled.
func (n *SystemdNotifier) Enabled() bool {
	return n.enabled
}

// Ready sends READY=1 to indicate the service is ready.
func (n *SystemdNotifier) Ready() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.enabled {
		return
	}
	if err := sdnotify.Ready(); err != nil {
		n.log.Warnf("failed to send READY=1: %v", err)
	} else {
		n.log.Debug("sent READY=1")
	}
}

// Reloading sends RELOADING=1 to indicate a reload is starting.
func (n *SystemdNotifier) Reloading() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.enabled {
		return
	}
	// Include monotonic timestamp for systemd tracking
	us := time.Since(n.startTime).Microseconds()
	status := fmt.Sprintf("RELOADING=1\nMONOTONIC_USEC=%d", us)
	if err := sdnotify.Status(status); err != nil {
		n.log.Warnf("failed to send RELOADING=1: %v", err)
	} else {
		n.log.Debugf("sent RELOADING=1 (MONOTONIC_USEC=%d)", us)
	}
}

// Stopping sends STOPPING=1 to indicate the service is stopping.
func (n *SystemdNotifier) Stopping() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.enabled {
		return
	}
	if err := sdnotify.Stopping(); err != nil {
		n.log.Warnf("failed to send STOPPING=1: %v", err)
	} else {
		n.log.Debug("sent STOPPING=1")
	}
}

// Status sends a custom status message.
func (n *SystemdNotifier) Status(status string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.enabled {
		return
	}
	if err := sdnotify.Status(status); err != nil {
		n.log.Warnf("failed to send STATUS=%s: %v", status, err)
	}
}

// Statusf sends a formatted status message.
func (n *SystemdNotifier) Statusf(format string, args ...interface{}) {
	n.Status(fmt.Sprintf(format, args...))
}

// ExtendTimeout extends the start/reload timeout.
// Use this during long operations to prevent systemd timeout.
func (n *SystemdNotifier) ExtendTimeout(d time.Duration) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.enabled {
		return
	}
	us := d.Microseconds()
	msg := fmt.Sprintf("EXTEND_TIMEOUT_USEC=%d", us)
	if err := sdnotify.Status(msg); err != nil {
		n.log.Warnf("failed to extend timeout: %v", err)
	} else {
		n.log.Debugf("extended timeout by %v", d)
	}
}

// Watchdog triggers the watchdog heartbeat.
func (n *SystemdNotifier) Watchdog() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.enabled {
		return
	}
	if err := sdnotify.Watchdog(); err != nil {
		n.log.Warnf("failed to trigger watchdog: %v", err)
	}
}

// ReloadErrno sends a reload error notification (Type=notify-reload).
// errno should be a numeric errno value (0 for success).
func (n *SystemdNotifier) ReloadErrno(errno int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.enabled {
		return
	}
	msg := fmt.Sprintf("RELOADERRNO=%d", errno)
	if err := sdnotify.Status(msg); err != nil {
		n.log.Warnf("failed to send RELOADERRNO=%d: %v", errno, err)
	} else {
		n.log.Debugf("sent RELOADERRNO=%d", errno)
	}
}

// NotifyReloading is a convenience method for Type=notify-reload services.
// It sends the full reloading notification with MONOTONIC_USEC.
func (n *SystemdNotifier) NotifyReloading() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.enabled {
		return
	}
	us := time.Since(n.startTime).Microseconds()
	// Format: RELOADING=1\nMONOTONIC_USEC=<microseconds>
	status := fmt.Sprintf("RELOADING=1\nMONOTONIC_USEC=%d", us)
	if err := sdnotify.Status(status); err != nil {
		n.log.Warnf("failed to send reloading notification: %v", err)
	} else {
		n.log.Debugf("sent reloading notification (MONOTONIC_USEC=%d)", us)
	}
}

// NotifyReady is a convenience method for Type=notify-reload services
// to indicate reload completion. Sends READY=1.
func (n *SystemdNotifier) NotifyReady() {
	n.Ready()
}
