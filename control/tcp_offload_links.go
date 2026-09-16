/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"io"
	"sync"
)

// tcpOffloadLinks owns the sk_skb stream-verdict link on fast_sock and the
// backlog-fuse accounting link for one bpfObjects set.
//
// bpfObjects survive config reloads (EjectBpf/InjectBpf handover), while
// every reload serves a fresh controlPlaneCore whose tcpSockmapOffloadReady
// starts false. Registering the links only in the per-core cleanup list
// therefore re-attaches on each reload while the previous generation's link
// is still alive, and the kernel rejects the second attach with EBUSY -
// silently disabling the offload on every other generation (repro: SIGUSR1
// reload with DAE_ALLOW_TCP_SOCKMAP=1). Reference-counting the links by the
// shared *bpfObjects keeps exactly one attach alive across reloads and
// closes it when the last plane referencing the objects goes away.
type tcpOffloadLinks struct {
	verdict io.Closer // sk_skb stream verdict on fast_sock
	account io.Closer // skb_send_sock fentry/kprobe; nil when accounting is disabled
}

type tcpOffloadLinkEntry struct {
	refs int
	l    tcpOffloadLinks
}

var (
	tcpOffloadLinkMu       sync.Mutex
	tcpOffloadLinkRegistry = map[*bpfObjects]*tcpOffloadLinkEntry{}
)

// attachTCPOffloadLinks takes a reference on the links already registered
// for bpf (reused=true), or attaches them via the callback and registers
// the result (reused=false). The callback must clean up after itself when
// it returns an error.
func attachTCPOffloadLinks(bpf *bpfObjects, attach func() (tcpOffloadLinks, error)) (reused bool, err error) {
	tcpOffloadLinkMu.Lock()
	defer tcpOffloadLinkMu.Unlock()
	if entry, ok := tcpOffloadLinkRegistry[bpf]; ok {
		entry.refs++
		return true, nil
	}
	links, err := attach()
	if err != nil {
		return false, err
	}
	tcpOffloadLinkRegistry[bpf] = &tcpOffloadLinkEntry{refs: 1, l: links}
	return false, nil
}

// releaseTCPOffloadLinks drops one reference taken by attachTCPOffloadLinks.
// The links are closed and unregistered once the last reference is gone.
func releaseTCPOffloadLinks(bpf *bpfObjects) {
	tcpOffloadLinkMu.Lock()
	entry := tcpOffloadLinkRegistry[bpf]
	if entry == nil {
		tcpOffloadLinkMu.Unlock()
		return
	}
	entry.refs--
	keep := entry.refs > 0
	if !keep {
		delete(tcpOffloadLinkRegistry, bpf)
	}
	l := entry.l
	tcpOffloadLinkMu.Unlock()
	if keep {
		return
	}
	closeQuietly(l.verdict)
	closeQuietly(l.account)
}

func closeQuietly(c io.Closer) {
	if c != nil {
		_ = c.Close()
	}
}
