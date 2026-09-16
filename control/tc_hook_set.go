/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"fmt"
	"maps"
	"sort"
	"sync"

	"github.com/cilium/ebpf"
	ciliumLink "github.com/cilium/ebpf/link"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type tcHookScope string

const (
	tcHookScopeHost tcHookScope = "host"
	tcHookScopeDae  tcHookScope = "dae"
)

type tcHookDirection uint8

const (
	tcHookIngress tcHookDirection = iota
	tcHookEgress
)

type tcHookGroupKey struct {
	scope     tcHookScope
	ifindex   int
	direction tcHookDirection
}

type tcHookKey struct {
	group    tcHookGroupKey
	priority uint16
}

type tcHookSpec struct {
	Scope     tcHookScope
	Ifindex   int
	Ifname    string
	Direction tcHookDirection
	Priority  uint16
	Handle    uint32
	Name      string
	Program   *ebpf.Program
	Run       func(func() error) error
}

func (s tcHookSpec) key() tcHookKey {
	return tcHookKey{
		group: tcHookGroupKey{
			scope:     s.Scope,
			ifindex:   s.Ifindex,
			direction: s.Direction,
		},
		priority: s.Priority,
	}
}

func (s tcHookSpec) validate() error {
	if s.Scope == "" {
		return fmt.Errorf("missing TC hook scope")
	}
	if s.Ifindex <= 0 {
		return fmt.Errorf("invalid TC hook ifindex %d", s.Ifindex)
	}
	if s.Direction != tcHookIngress && s.Direction != tcHookEgress {
		return fmt.Errorf("invalid TC hook direction %d", s.Direction)
	}
	if s.Priority == 0 {
		return fmt.Errorf("invalid TC hook priority 0")
	}
	if s.Program == nil {
		return fmt.Errorf("missing TC hook program")
	}
	return nil
}

func (s tcHookSpec) parent() uint32 {
	if s.Direction == tcHookIngress {
		return netlink.HANDLE_MIN_INGRESS
	}
	return netlink.HANDLE_MIN_EGRESS
}

func (s tcHookSpec) attachType() ebpf.AttachType {
	if s.Direction == tcHookIngress {
		return ebpf.AttachTCXIngress
	}
	return ebpf.AttachTCXEgress
}

func (s tcHookSpec) filter() *netlink.BpfFilter {
	return &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: s.Ifindex,
			Parent:    s.parent(),
			Handle:    s.Handle,
			Protocol:  unix.ETH_P_ALL,
			Priority:  s.Priority,
		},
		Fd:           s.Program.FD(),
		Name:         s.Name,
		DirectAction: true,
	}
}

func (s tcHookSpec) run(operation func() error) error {
	if s.Run == nil {
		return operation()
	}
	return s.Run(operation)
}

type tcxHookAttachment interface {
	Update(*ebpf.Program) error
	Close() error
}

type realTCXHookAttachment struct {
	link ciliumLink.Link
}

func (a *realTCXHookAttachment) Update(program *ebpf.Program) error {
	return a.link.Update(program)
}

func (a *realTCXHookAttachment) Close() error {
	return a.link.Close()
}

type tcxHookPosition struct {
	head   bool
	before tcxHookAttachment
	after  tcxHookAttachment
}

type tcHookBackend struct {
	classicFiltersPresent func(tcHookSpec) (bool, error)
	attachTCX             func(tcHookSpec, tcxHookPosition) (tcxHookAttachment, error)
	replaceClassic        func(tcHookSpec) error
	deleteClassic         func(tcHookSpec) error
}

func newRealTCHookBackend() tcHookBackend {
	return tcHookBackend{
		classicFiltersPresent: func(spec tcHookSpec) (present bool, err error) {
			err = spec.run(func() error {
				filters, listErr := netlink.FilterList(
					&tcHookNetlinkLink{attrs: netlink.LinkAttrs{Index: spec.Ifindex, Name: spec.Ifname}},
					spec.parent(),
				)
				if listErr != nil {
					if stderrors.Is(listErr, unix.ENOENT) || stderrors.Is(listErr, unix.ESRCH) || stderrors.Is(listErr, unix.ENODEV) {
						return nil
					}
					return listErr
				}
				present = len(filters) != 0
				return nil
			})
			return present, err
		},
		attachTCX: func(spec tcHookSpec, position tcxHookPosition) (tcxHookAttachment, error) {
			opts := ciliumLink.TCXOptions{
				Interface: spec.Ifindex,
				Program:   spec.Program,
				Attach:    spec.attachType(),
			}
			switch {
			case position.head:
				opts.Anchor = ciliumLink.Head()
			case position.before != nil:
				anchor, ok := position.before.(*realTCXHookAttachment)
				if !ok {
					return nil, fmt.Errorf("invalid TCX before anchor %T", position.before)
				}
				opts.Anchor = ciliumLink.BeforeLink(anchor.link)
			case position.after != nil:
				anchor, ok := position.after.(*realTCXHookAttachment)
				if !ok {
					return nil, fmt.Errorf("invalid TCX after anchor %T", position.after)
				}
				opts.Anchor = ciliumLink.AfterLink(anchor.link)
			}
			var attached ciliumLink.Link
			err := spec.run(func() error {
				var err error
				attached, err = ciliumLink.AttachTCX(opts)
				return err
			})
			if err != nil {
				return nil, err
			}
			return &realTCXHookAttachment{link: attached}, nil
		},
		replaceClassic: func(spec tcHookSpec) error {
			return spec.run(func() error {
				return netlink.FilterReplace(spec.filter())
			})
		},
		deleteClassic: func(spec tcHookSpec) error {
			return spec.run(func() error {
				return deleteTCFiltersByHandle(
					&tcHookNetlinkLink{attrs: netlink.LinkAttrs{Index: spec.Ifindex, Name: spec.Ifname}},
					spec.parent(),
					spec.Handle,
				)
			})
		},
	}
}

// tcHookNetlinkLink supplies the stable attributes needed by FilterList. The
// kernel lookup is by ifindex, so retaining a netlink.Link implementation from a
// deleted interface would only preserve stale userspace metadata.
type tcHookNetlinkLink struct {
	attrs netlink.LinkAttrs
}

func (l *tcHookNetlinkLink) Attrs() *netlink.LinkAttrs { return &l.attrs }
func (l *tcHookNetlinkLink) Type() string              { return "tc-hook" }

type tcHookMode uint8

const (
	tcHookModeUnknown tcHookMode = iota
	tcHookModeTCX
	tcHookModeClassic
)

type tcHookEntry struct {
	spec tcHookSpec
	tcx  tcxHookAttachment
}

type tcHookGroup struct {
	mode    tcHookMode
	entries map[uint16]*tcHookEntry
}

type tcHookTransaction struct {
	before      map[tcHookKey]tcHookSpec
	beforeModes map[tcHookGroupKey]tcHookMode
	desired     map[tcHookKey]tcHookSpec
	committed   bool
	// partial records that commit() applied part of the desired state and
	// its internal restore attempt also failed: kernel TC state no longer
	// matches `before`, so rollback/abort must re-apply the snapshot
	// instead of discarding the transaction (and the only record of the
	// pre-transaction state) without restoring it.
	partial bool
}

// tcHookSet owns every TC attachment for one active datapath generation. Its
// transaction Interface hides TCX links, classic filters, ordering, rollback,
// and namespace switching from reload orchestration.
type tcHookSet struct {
	mu      sync.Mutex
	log     *logrus.Logger
	backend tcHookBackend
	groups  map[tcHookGroupKey]*tcHookGroup
	txn     *tcHookTransaction
	closed  bool
}

func newTCHookSet(log *logrus.Logger) *tcHookSet {
	return newTCHookSetWithBackend(log, newRealTCHookBackend())
}

func newTCHookSetWithBackend(log *logrus.Logger, backend tcHookBackend) *tcHookSet {
	return &tcHookSet{
		log:     log,
		backend: backend,
		groups:  make(map[tcHookGroupKey]*tcHookGroup),
	}
}

func (s *tcHookSet) beginReplace() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("TC HookSet is closed")
	}
	if s.txn != nil {
		return fmt.Errorf("TC HookSet transaction already active")
	}
	s.txn = &tcHookTransaction{
		before:      s.currentSpecsLocked(),
		beforeModes: s.currentModesLocked(),
		desired:     make(map[tcHookKey]tcHookSpec),
	}
	return nil
}

func (s *tcHookSet) stage(spec tcHookSpec) error {
	if err := spec.validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.txn == nil {
		return fmt.Errorf("TC HookSet transaction is not active")
	}
	if s.txn.committed {
		return fmt.Errorf("TC HookSet transaction is already committed")
	}
	s.txn.desired[spec.key()] = spec
	return nil
}

func (s *tcHookSet) stageRemoveInterface(scope tcHookScope, ifindex int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.txn == nil {
		return fmt.Errorf("TC HookSet transaction is not active")
	}
	if s.txn.committed {
		return fmt.Errorf("TC HookSet transaction is already committed")
	}
	for key := range s.txn.desired {
		if key.group.scope == scope && key.group.ifindex == ifindex {
			delete(s.txn.desired, key)
		}
	}
	return nil
}

func (s *tcHookSet) commit() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.txn == nil {
		return fmt.Errorf("TC HookSet transaction is not active")
	}
	if s.txn.committed {
		return nil
	}
	if err := s.applyDesiredLocked(s.txn.desired); err != nil {
		rollbackErr := s.applyDesiredLocked(s.txn.before)
		if rollbackErr == nil {
			s.restoreModesLocked(s.txn.beforeModes)
			s.txn = nil
			s.pruneEmptyGroupsLocked()
		} else {
			// Keep the transaction, marked partial: the kernel no longer
			// matches `before`, and a later rollback()/abort() must still
			// restore the snapshot rather than discard it.
			s.txn.partial = true
		}
		return stderrors.Join(err, rollbackErr)
	}
	s.txn.committed = true
	return nil
}

func (s *tcHookSet) rollback() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.txn == nil {
		return nil
	}
	if !s.txn.committed {
		if s.txn.partial {
			// commit() left the kernel partially applied and its internal
			// restore failed. Discarding `before` now would strand
			// retired-generation programs on the interfaces until the next
			// successful reload, so restore the snapshot instead. On
			// failure keep the transaction for a retry.
			if err := s.applyDesiredLocked(s.txn.before); err != nil {
				return err
			}
			s.restoreModesLocked(s.txn.beforeModes)
		}
		s.txn = nil
		s.pruneEmptyGroupsLocked()
		return nil
	}
	if err := s.applyDesiredLocked(s.txn.before); err != nil {
		return err
	}
	s.restoreModesLocked(s.txn.beforeModes)
	s.txn = nil
	s.pruneEmptyGroupsLocked()
	return nil
}

func (s *tcHookSet) finalize() {
	s.mu.Lock()
	if s.txn != nil && s.txn.committed {
		s.txn = nil
	}
	s.pruneEmptyGroupsLocked()
	s.mu.Unlock()
}

func (s *tcHookSet) abort() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.txn == nil {
		return nil
	}
	if s.txn.committed {
		return fmt.Errorf("cannot abort committed TC HookSet transaction")
	}
	if s.txn.partial {
		// Same rationale as rollback(): commit() already moved kernel
		// state, so the pre-transaction snapshot must be restored, not
		// dropped. Keep the transaction on failure for a retry.
		if err := s.applyDesiredLocked(s.txn.before); err != nil {
			return err
		}
		s.restoreModesLocked(s.txn.beforeModes)
	}
	s.txn = nil
	s.pruneEmptyGroupsLocked()
	return nil
}

func (s *tcHookSet) upsert(spec tcHookSpec) error {
	if err := spec.validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("TC HookSet is closed")
	}
	if s.txn != nil {
		return fmt.Errorf("TC HookSet transaction is active")
	}
	before := s.currentSpecsLocked()
	desired := cloneTCHookSpecs(before)
	desired[spec.key()] = spec
	if err := s.applyDesiredLocked(desired); err != nil {
		return stderrors.Join(err, s.applyDesiredLocked(before))
	}
	s.pruneEmptyGroupsLocked()
	return nil
}

func (s *tcHookSet) removeInterface(scope tcHookScope, ifindex int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if s.txn != nil {
		return fmt.Errorf("TC HookSet transaction is active")
	}
	before := s.currentSpecsLocked()
	desired := cloneTCHookSpecs(before)
	for key := range desired {
		if key.group.scope == scope && key.group.ifindex == ifindex {
			delete(desired, key)
		}
	}
	if err := s.applyDesiredLocked(desired); err != nil {
		return stderrors.Join(err, s.applyDesiredLocked(before))
	}
	s.pruneEmptyGroupsLocked()
	return nil
}

func (s *tcHookSet) isClosed() bool {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	return closed
}

func (s *tcHookSet) hasTransaction() bool {
	s.mu.Lock()
	active := s.txn != nil
	s.mu.Unlock()
	return active
}

func (s *tcHookSet) empty() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, group := range s.groups {
		if len(group.entries) != 0 {
			return false
		}
	}
	return true
}

func (s *tcHookSet) close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if err := s.applyDesiredLocked(map[tcHookKey]tcHookSpec{}); err != nil {
		return err
	}
	s.txn = nil
	s.groups = make(map[tcHookGroupKey]*tcHookGroup)
	s.closed = true
	return nil
}

func (s *tcHookSet) currentSpecsLocked() map[tcHookKey]tcHookSpec {
	specs := make(map[tcHookKey]tcHookSpec)
	for groupKey, group := range s.groups {
		for priority, entry := range group.entries {
			specs[tcHookKey{group: groupKey, priority: priority}] = entry.spec
		}
	}
	return specs
}

func (s *tcHookSet) currentModesLocked() map[tcHookGroupKey]tcHookMode {
	modes := make(map[tcHookGroupKey]tcHookMode, len(s.groups))
	for key, group := range s.groups {
		modes[key] = group.mode
	}
	return modes
}

func (s *tcHookSet) restoreModesLocked(modes map[tcHookGroupKey]tcHookMode) {
	for key, mode := range modes {
		if group := s.groups[key]; group != nil {
			group.mode = mode
		}
	}
}

func (s *tcHookSet) applyDesiredLocked(desired map[tcHookKey]tcHookSpec) error {
	for _, key := range sortedTCHookKeys(desired, false) {
		spec := desired[key]
		group := s.groups[key.group]
		if group == nil {
			group = &tcHookGroup{entries: make(map[uint16]*tcHookEntry)}
			s.groups[key.group] = group
		}
		entry := group.entries[key.priority]
		if entry == nil {
			if err := s.attachLocked(group, spec); err != nil {
				return fmt.Errorf("attach TC hook %s on %s: %w", spec.Name, spec.Ifname, err)
			}
			continue
		}
		if entry.spec.Program == spec.Program {
			entry.spec = spec
			continue
		}
		if err := s.updateLocked(group, entry, spec); err != nil {
			return fmt.Errorf("update TC hook %s on %s: %w", spec.Name, spec.Ifname, err)
		}
	}

	current := s.currentSpecsLocked()
	for _, key := range sortedTCHookKeys(current, true) {
		if _, keep := desired[key]; keep {
			continue
		}
		group := s.groups[key.group]
		entry := group.entries[key.priority]
		err := s.detachLocked(group, entry)
		// close(2) and netlink ACK failures can be reported after the kernel
		// has already detached the hook. Model the requested post-state so a
		// transaction rollback reattaches/replaces the snapshot unconditionally.
		delete(group.entries, key.priority)
		if err != nil {
			return fmt.Errorf("detach TC hook %s on %s: %w", entry.spec.Name, entry.spec.Ifname, err)
		}
	}
	return nil
}

func (s *tcHookSet) attachLocked(group *tcHookGroup, spec tcHookSpec) error {
	switch group.mode {
	case tcHookModeUnknown:
		classicPresent, err := s.backend.classicFiltersPresent(spec)
		if err != nil {
			return fmt.Errorf("inspect existing classic TC filters: %w", err)
		}
		if classicPresent {
			group.mode = tcHookModeClassic
			if s.log != nil {
				s.log.WithField("interface", spec.Ifname).Debug("classic TC filters already present; preserving classic priority ordering")
			}
			return s.attachLocked(group, spec)
		}
		attached, err := s.backend.attachTCX(spec, tcxPositionForPriority(group, spec.Priority))
		if err == nil {
			group.mode = tcHookModeTCX
			group.entries[spec.Priority] = &tcHookEntry{spec: spec, tcx: attached}
			return nil
		}
		if !stderrors.Is(err, ciliumLink.ErrNotSupported) {
			return err
		}
		group.mode = tcHookModeClassic
		if s.log != nil {
			s.log.WithField("interface", spec.Ifname).Debug("TCX unavailable; using classic TC filter replacement")
		}
		fallthrough
	case tcHookModeClassic:
		if err := s.backend.replaceClassic(spec); err != nil {
			// Netlink may apply RTM_NEWTFILTER before an ACK/read failure. Treat
			// the requested state as uncertain-but-present so rollback always
			// issues the inverse operation instead of trusting the error alone.
			group.entries[spec.Priority] = &tcHookEntry{spec: spec}
			return err
		}
		group.entries[spec.Priority] = &tcHookEntry{spec: spec}
		return nil
	case tcHookModeTCX:
		attached, err := s.backend.attachTCX(spec, tcxPositionForPriority(group, spec.Priority))
		if err != nil {
			return err
		}
		group.entries[spec.Priority] = &tcHookEntry{spec: spec, tcx: attached}
		return nil
	default:
		return fmt.Errorf("invalid TC hook mode %d", group.mode)
	}
}

func (s *tcHookSet) updateLocked(group *tcHookGroup, entry *tcHookEntry, spec tcHookSpec) error {
	switch group.mode {
	case tcHookModeTCX:
		if entry.tcx == nil {
			return fmt.Errorf("missing TCX link")
		}
		if err := entry.tcx.Update(spec.Program); err != nil {
			entry.spec = spec
			return err
		}
	case tcHookModeClassic:
		if err := s.backend.replaceClassic(spec); err != nil {
			// A netlink ACK/read error does not prove FilterReplace was not
			// applied. Record the requested state so rollback replaces it with
			// the snapshot program even when the backend returned an error.
			entry.spec = spec
			return err
		}
	default:
		return fmt.Errorf("cannot update TC hook in mode %d", group.mode)
	}
	entry.spec = spec
	return nil
}

func (s *tcHookSet) detachLocked(group *tcHookGroup, entry *tcHookEntry) error {
	switch group.mode {
	case tcHookModeTCX:
		if entry.tcx == nil {
			return nil
		}
		return entry.tcx.Close()
	case tcHookModeClassic:
		return s.backend.deleteClassic(entry.spec)
	default:
		return nil
	}
}

func (s *tcHookSet) pruneEmptyGroupsLocked() {
	for key, group := range s.groups {
		if len(group.entries) == 0 {
			delete(s.groups, key)
		}
	}
}

func tcxPositionForPriority(group *tcHookGroup, priority uint16) tcxHookPosition {
	var lowerPriority uint16
	var lower tcxHookAttachment
	var higherPriority uint16
	var higher tcxHookAttachment
	for currentPriority, entry := range group.entries {
		if entry.tcx == nil {
			continue
		}
		if currentPriority < priority && (lower == nil || currentPriority > lowerPriority) {
			lowerPriority = currentPriority
			lower = entry.tcx
		}
		if currentPriority > priority && (higher == nil || currentPriority < higherPriority) {
			higherPriority = currentPriority
			higher = entry.tcx
		}
	}
	if lower != nil {
		return tcxHookPosition{after: lower}
	}
	if higher != nil {
		return tcxHookPosition{before: higher}
	}
	return tcxHookPosition{head: true}
}

func cloneTCHookSpecs(specs map[tcHookKey]tcHookSpec) map[tcHookKey]tcHookSpec {
	cloned := make(map[tcHookKey]tcHookSpec, len(specs))
	maps.Copy(cloned, specs)
	return cloned
}

func sortedTCHookKeys(specs map[tcHookKey]tcHookSpec, reverse bool) []tcHookKey {
	keys := make([]tcHookKey, 0, len(specs))
	for key := range specs {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		left, right := keys[i], keys[j]
		switch {
		case left.group.scope != right.group.scope:
			return left.group.scope < right.group.scope
		case left.group.ifindex != right.group.ifindex:
			return left.group.ifindex < right.group.ifindex
		case left.group.direction != right.group.direction:
			return left.group.direction < right.group.direction
		default:
			return left.priority < right.priority
		}
	})
	if reverse {
		for left, right := 0, len(keys)-1; left < right; left, right = left+1, right-1 {
			keys[left], keys[right] = keys[right], keys[left]
		}
	}
	return keys
}
