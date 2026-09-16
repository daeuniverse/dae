/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
)

func dnsCachePolicyEqual(oldConf, newConf *config.Config) bool {
	if oldConf == nil || newConf == nil {
		return false
	}
	oldDNS, newDNS := oldConf.Dns, newConf.Dns
	// The listener address does not change which answers DNS policy accepts.
	oldDNS.Bind, newDNS.Bind = "", ""
	return dnsConfigFingerprint(oldDNS) == dnsConfigFingerprint(newDNS)
}

func cloneReloadDNSCaches(oldConf, newConf *config.Config, stagedHotHandoff bool, cloneCache func() map[string]*control.DnsCache) (candidate, rollback map[string]*control.DnsCache) {
	preserveAnswers := dnsCachePolicyEqual(oldConf, newConf)
	stream := shouldStreamStagedDnsCache(stagedHotHandoff, dnsConfigEqual(oldConf, newConf), preserveAnswers)
	if stream || (stagedHotHandoff && !preserveAnswers) {
		// A staged failure keeps the old controller alive; unchanged DNS uses
		// its authoritative stream at cutover instead of a preparation clone.
		return nil, nil
	}
	snapshot := cloneCache()
	if preserveAnswers {
		candidate = snapshot
	}
	if !stagedHotHandoff {
		// Legacy rollback rebuilds the old policy, even if the candidate must
		// discard its answers. Never invalidate the active controller's cache.
		rollback = snapshot
	}
	return candidate, rollback
}
