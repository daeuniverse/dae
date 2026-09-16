/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
)

func (c *ControlPlane) closePublishedListenerFiles() error {
	if c == nil {
		return nil
	}

	c.listenerPublishMu.Lock()
	files := c.listenerFiles
	c.listenerFiles = nil
	c.listenerPublishMu.Unlock()

	var errs []error
	for _, f := range files {
		if f == nil {
			continue
		}
		if err := f.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return stderrors.Join(errs...)
}

func (c *ControlPlane) publishListenerSockets(listener *Listener) error {
	if c == nil || c.core == nil || listener == nil {
		return fmt.Errorf("publishListenerSockets: nil control plane or listener")
	}
	bpf := c.core.bpf.Load()
	if bpf == nil || bpf.ListenSocketMap == nil {
		return fmt.Errorf("publishListenerSockets: listen socket map is unavailable")
	}

	var (
		newFiles []*os.File
		err      error
	)
	closeNewFiles := func() {
		for _, f := range newFiles {
			if f != nil {
				_ = f.Close()
			}
		}
	}

	if listener.tcp4Listener != nil {
		tcp4File, e := dupTCPListenerFile(listener.tcp4Listener)
		if e != nil {
			return fmt.Errorf("failed to retrieve copy of the underlying TCP IPv4 listener file")
		}
		newFiles = append(newFiles, tcp4File)
		if err = bpf.ListenSocketMap.Update(consts.ZeroKey, uint64(tcp4File.Fd()), ebpf.UpdateAny); err != nil {
			closeNewFiles()
			return err
		}
	}
	if listener.tcp6Listener != nil {
		tcp6File, e := dupTCPListenerFile(listener.tcp6Listener)
		if e != nil {
			closeNewFiles()
			return fmt.Errorf("failed to retrieve copy of the underlying TCP IPv6 listener file")
		}
		newFiles = append(newFiles, tcp6File)
		if err = bpf.ListenSocketMap.Update(consts.TwoKey, uint64(tcp6File.Fd()), ebpf.UpdateAny); err != nil {
			closeNewFiles()
			return err
		}
	}
	if listener.packetConn != nil {
		udpFile, e := dupUDPPacketConnFile(listener.packetConn)
		if e != nil {
			closeNewFiles()
			return fmt.Errorf("failed to retrieve copy of the underlying UDP connection file")
		}
		newFiles = append(newFiles, udpFile)
		if err = bpf.ListenSocketMap.Update(consts.OneKey, uint64(udpFile.Fd()), ebpf.UpdateAny); err != nil {
			closeNewFiles()
			return err
		}
	}

	c.listenerPublishMu.Lock()
	oldFiles := c.listenerFiles
	c.listenerFiles = newFiles
	c.listenerPublishMu.Unlock()
	for _, f := range oldFiles {
		if f != nil {
			_ = f.Close()
		}
	}
	return nil
}

func (c *ControlPlane) PublishListenerSockets(listener *Listener) error {
	return c.publishListenerSockets(listener)
}

func (c *ControlPlane) commitInterfaceBindings() (err error) {
	if c == nil || c.core == nil {
		return nil
	}
	c.core.configureTCHookPatterns(c.lanInterface, c.wanInterface)
	if err = c.core.beginTCHookReplace(); err != nil {
		return fmt.Errorf("begin TC HookSet transaction: %w", err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		if abortErr := c.core.abortTCHookReplace(); abortErr != nil {
			err = stderrors.Join(err, abortErr)
		}
	}()

	if len(c.lanInterface) > 0 {
		if c.autoConfigKernelParameter {
			if err := SetIpv4forward("1"); err != nil {
				c.log.WithError(err).Warnln("Failed to enable IPv4 forwarding; proxy functionality may be limited")
			}
			if err := setForwarding("all", consts.IpVersionStr_6, "1"); err != nil {
				c.log.WithError(err).Warnln("Failed to enable IPv6 forwarding; proxy functionality may be limited")
			}
		}
		c.lanInterface = common.Deduplicate(c.lanInterface)
		for _, ifname := range c.lanInterface {
			if err := c.core.bindLan(ifname, c.autoConfigKernelParameter); err != nil {
				return fmt.Errorf("bind LAN interface %s: %w", ifname, err)
			}
		}
	}

	if len(c.wanInterface) > 0 {
		if err := c.core.setupSkPidMonitor(); err != nil {
			c.log.WithError(err).Warnln("cgroup2 is not enabled; pname routing cannot be used")
		}
		if err := c.core.setupTCPRelayOffload(); err != nil {
			c.log.WithError(err).Warnln("TCP relay eBPF offload disabled; the accounting hook may already be attached by another eBPF program (check 'bpftool link list')")
		}
		for _, ifname := range c.wanInterface {
			if len(c.lanInterface) > 0 && c.autoConfigKernelParameter {
				acceptRa := sysctl.Keyf("net.ipv6.conf.%v.accept_ra", ifname)
				val, err := acceptRa.Get()
				if err == nil && val == "1" {
					if err := acceptRa.Set("2", false); err != nil {
						c.log.WithError(err).Warnf("Failed to set accept_ra=2 for %v; IPv6 autoconfig may not work as expected", ifname)
					}
				}
			}
			if err := c.core.bindWan(ifname); err != nil {
				return fmt.Errorf("bind WAN interface %s: %w", ifname, err)
			}
		}
	}

	if err := c.core.bindDaens(); err != nil {
		return fmt.Errorf("bindDaens: %w", err)
	}
	if err := c.core.commitTCHookReplace(); err != nil {
		return fmt.Errorf("commit TC HookSet transaction: %w", err)
	}
	committed = true
	return nil
}

func (c *ControlPlane) replayDnsReloadCache() error {
	if c == nil || c.dnsController == nil || c.pendingDnsReloadCache == nil {
		return nil
	}
	start := time.Now()
	count, err := c.dnsController.RestoreReloadCacheAndProject(
		c.pendingDnsReloadCache,
		c.routingMatcher.domainMatcher.MatchDomainBitmap,
		time.Now(),
	)
	if err != nil {
		return err
	}
	if count > 0 {
		c.log.Infof("Restored %d DNS cache entries from previous control plane in %v", count, time.Since(start))
	}
	c.pendingDnsReloadCache = nil
	return nil
}

// releaseCommittedDNSReloadState drops candidate-local cache replay state once
// the prepared routing epoch has committed successfully.
func (c *ControlPlane) releaseCommittedDNSReloadState() {
	if c == nil {
		return
	}
	c.pendingDnsReloadCache = nil
	c.ClearReloadDnsCacheSource()
}

// CommitPreparedDatapath applies deferred kernel/BPF mutations for a prepared
// control plane. It is safe to call once; subsequent calls are no-ops.
func (c *ControlPlane) CommitPreparedDatapath() error {
	if c == nil || !c.preparedDatapathCommit {
		return nil
	}
	if c.core == nil {
		c.releaseCommittedDNSReloadState()
		c.startConnStateJanitor()
		c.preparedDatapathCommit = false
		return nil
	}
	if c.routingKernspaceSnapshot != nil {
		c.log.Infoln("Loading routing rules into kernel space (BPF)...")
		if err := c.core.buildRoutingKernspaceForSlot(c.log, c.routingKernspaceSnapshot); err != nil {
			return fmt.Errorf("routing kernspace snapshot: %w", err)
		}
		if err := c.core.StageRoutingEpoch(); err != nil {
			return fmt.Errorf("stage routing epoch: %w", err)
		}
	}
	refreshedDnsReloadCache, err := c.refreshDnsReloadCacheForCutover()
	if err != nil {
		return fmt.Errorf("refresh DNS reload cache for cutover: %w", err)
	}
	if err := c.replayDnsReloadCache(); err != nil {
		return fmt.Errorf("replay DNS reload cache: %w", err)
	}
	if refreshedDnsReloadCache {
		c.ClearReloadDnsCacheSource()
	}
	// Publishing the prepared slot is the atomic cutover: until this
	// succeeds the kernel keeps routing through the previous slot, so a
	// failure above leaves the old policy serving rather than a half-written
	// new one.
	if err := c.publishRoutingEpoch(); err != nil {
		return fmt.Errorf("publish routing epoch: %w", err)
	}
	if c.bpfMaintenance != nil {
		if err := c.activateBpfMaintenance(); err != nil {
			if rollbackErr := c.rollbackRoutingEpoch(); rollbackErr != nil {
				return stderrors.Join(err, rollbackErr)
			}
			return err
		}
	}
	c.releaseCommittedDNSReloadState()
	c.preparedDatapathCommit = false
	return nil
}

// CommitPreparedBpfHookFlip commits the candidate's borrowed HookSet and then
// publishes its userspace generation marker. Until this call, prepared shared
// and isolated candidates own no TC hook mutation. Any failure synchronously
// restores the previous HookSet before candidate-local hooks are detached.
func (c *ControlPlane) CommitPreparedBpfHookFlip() error {
	return c.commitPreparedBpfHookFlip(c.commitInterfaceBindings)
}

func (c *ControlPlane) commitPreparedBpfHookFlip(commitBindings func() error) error {
	if c == nil || c.core == nil {
		return nil
	}
	if err := commitBindings(); err != nil {
		return stderrors.Join(err, c.core.DetachBpfHooks())
	}
	if err := c.core.commitBpfHookFlip(); err != nil {
		return stderrors.Join(
			err,
			c.core.rollbackPreparedTCHooks(),
			c.core.DetachBpfHooks(),
		)
	}
	return nil
}

// RollbackPreparedBpfHookFlip restores every previous TC program and the
// previous userspace generation marker after supervisor publication fails.
func (c *ControlPlane) RollbackPreparedBpfHookFlip() error {
	if c == nil || c.core == nil {
		return nil
	}
	return stderrors.Join(
		c.core.rollbackPreparedTCHooks(),
		c.core.rollbackCommittedBpfHookFlip(),
	)
}

// RebuildReloadDatapath restores this generation's datapath after a staged
// reload attempt modified shared BPF state but failed before cutover completed.
func (c *ControlPlane) RebuildReloadDatapath() error {
	if c == nil || c.routingKernspaceSnapshot == nil || c.core == nil || c.core.PeekBpf() == nil {
		return nil
	}
	c.log.Warnln("[Reload] Rolling back to the previous routing epoch after staged handoff failure")
	if err := c.publishRoutingEpoch(); err != nil {
		return fmt.Errorf("publish previous routing epoch: %w", err)
	}
	c.core.activateBpfHookFlip()
	return nil
}

// RestoreDatapathForReloadRollback reattaches this generation's kernel hooks
// and restores routing/DNS maps after a prepared fresh-datapath reload failed
// during cutover.
func (c *ControlPlane) RestoreDatapathForReloadRollback() error {
	if c == nil || c.core == nil || c.core.PeekBpf() == nil {
		return nil
	}
	c.log.Warnln("[Reload] Restoring previous generation datapath after fresh handoff failure")
	c.core.resetBpfHookDetachForReattach()
	if err := c.commitInterfaceBindings(); err != nil {
		return fmt.Errorf("restore interface bindings: %w", err)
	}
	if c.routingKernspaceSnapshot != nil {
		if err := c.core.buildRoutingKernspaceForSlot(c.log, c.routingKernspaceSnapshot); err != nil {
			return fmt.Errorf("restore routing kernspace: %w", err)
		}
		if err := c.core.StageRoutingEpoch(); err != nil {
			return fmt.Errorf("restore routing epoch: %w", err)
		}
	}
	if err := c.core.clearDomainRoutingSlot(c.core.RoutingEpochSlot()); err != nil {
		return fmt.Errorf("restore clear domain routing slot: %w", err)
	}
	c.pendingDnsReloadCache = c.CloneDnsCache()
	if err := c.replayDnsReloadCache(); err != nil {
		return fmt.Errorf("restore DNS reload cache: %w", err)
	}
	if err := c.publishRoutingEpoch(); err != nil {
		return fmt.Errorf("restore publish routing epoch: %w", err)
	}
	c.core.activateBpfHookFlip()
	return nil
}
