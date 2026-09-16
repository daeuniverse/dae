/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"testing"

	"github.com/cilium/ebpf"
	ciliumLink "github.com/cilium/ebpf/link"
	"github.com/sirupsen/logrus"
)

type fakeTCXHook struct {
	backend *fakeTCHookBackend
	program *ebpf.Program
	closed  bool
}

func (h *fakeTCXHook) Update(program *ebpf.Program) error {
	h.backend.updates = append(h.backend.updates, program)
	if program == h.backend.failUpdateProgram {
		if h.backend.applyUpdateBeforeError {
			h.program = program
		}
		return h.backend.updateErr
	}
	h.program = program
	return nil
}

func (h *fakeTCXHook) Close() error {
	h.closed = true
	h.backend.closed++
	if h.backend.closeErr != nil {
		err := h.backend.closeErr
		h.backend.closeErr = nil
		return err
	}
	return nil
}

type fakeTCXAttach struct {
	spec     tcHookSpec
	position tcxHookPosition
	hook     *fakeTCXHook
}

type fakeClassicReplace struct {
	spec tcHookSpec
}

type fakeTCHookBackend struct {
	classicFiltersPresent   bool
	classicFilterInspectErr error
	attachErr               error
	updateErr               error
	failUpdateProgram       *ebpf.Program
	applyUpdateBeforeError  bool
	failReplaceProgram      *ebpf.Program
	replaceErr              error
	closeErr                error
	attachments             []fakeTCXAttach
	updates                 []*ebpf.Program
	classicReplaces         []fakeClassicReplace
	classicDeletes          []tcHookSpec
	closed                  int
}

func (b *fakeTCHookBackend) moduleBackend() tcHookBackend {
	return tcHookBackend{
		classicFiltersPresent: func(tcHookSpec) (bool, error) {
			return b.classicFiltersPresent, b.classicFilterInspectErr
		},
		attachTCX: func(spec tcHookSpec, position tcxHookPosition) (tcxHookAttachment, error) {
			if b.attachErr != nil {
				return nil, b.attachErr
			}
			hook := &fakeTCXHook{backend: b, program: spec.Program}
			b.attachments = append(b.attachments, fakeTCXAttach{spec: spec, position: position, hook: hook})
			return hook, nil
		},
		replaceClassic: func(spec tcHookSpec) error {
			b.classicReplaces = append(b.classicReplaces, fakeClassicReplace{spec: spec})
			if spec.Program == b.failReplaceProgram {
				return b.replaceErr
			}
			return nil
		},
		deleteClassic: func(spec tcHookSpec) error {
			b.classicDeletes = append(b.classicDeletes, spec)
			return nil
		},
	}
}

func testTCHookSpec(priority uint16, program *ebpf.Program) tcHookSpec {
	return tcHookSpec{
		Scope:     tcHookScopeHost,
		Ifindex:   7,
		Ifname:    "test0",
		Direction: tcHookIngress,
		Priority:  priority,
		Handle:    uint32(priority) << 1,
		Name:      "test",
		Program:   program,
	}
}

func TestTCHookSetOrdersTCXGroupByPriority(t *testing.T) {
	backend := &fakeTCHookBackend{}
	set := newTCHookSetWithBackend(logrus.New(), backend.moduleBackend())
	priority1 := new(ebpf.Program)
	priority2 := new(ebpf.Program)

	if err := set.beginReplace(); err != nil {
		t.Fatal(err)
	}
	if err := set.stage(testTCHookSpec(2, priority2)); err != nil {
		t.Fatal(err)
	}
	if err := set.stage(testTCHookSpec(1, priority1)); err != nil {
		t.Fatal(err)
	}
	if err := set.commit(); err != nil {
		t.Fatal(err)
	}
	set.finalize()

	if len(backend.attachments) != 2 {
		t.Fatalf("attachments=%d, want 2", len(backend.attachments))
	}
	first, second := backend.attachments[0], backend.attachments[1]
	if first.spec.Priority != 1 || !first.position.head {
		t.Fatalf("first attachment priority/head = %d/%t, want 1/true", first.spec.Priority, first.position.head)
	}
	if second.spec.Priority != 2 || second.position.after != first.hook {
		t.Fatalf("second attachment priority/anchor = %d/%T, want priority 2 after first", second.spec.Priority, second.position.after)
	}
}

func TestTCHookSetRollsBackPartialTCXUpdate(t *testing.T) {
	backend := &fakeTCHookBackend{updateErr: stderrors.New("injected update failure")}
	set := newTCHookSetWithBackend(logrus.New(), backend.moduleBackend())
	old1, old2 := new(ebpf.Program), new(ebpf.Program)
	new1, new2 := new(ebpf.Program), new(ebpf.Program)

	if err := set.beginReplace(); err != nil {
		t.Fatal(err)
	}
	_ = set.stage(testTCHookSpec(1, old1))
	_ = set.stage(testTCHookSpec(2, old2))
	if err := set.commit(); err != nil {
		t.Fatal(err)
	}
	set.finalize()

	backend.failUpdateProgram = new2
	if err := set.beginReplace(); err != nil {
		t.Fatal(err)
	}
	_ = set.stage(testTCHookSpec(1, new1))
	_ = set.stage(testTCHookSpec(2, new2))
	if err := set.commit(); !stderrors.Is(err, backend.updateErr) {
		t.Fatalf("commit error = %v, want injected update failure", err)
	}
	wantUpdates := []*ebpf.Program{new1, new2, old1, old2}
	if len(backend.updates) != len(wantUpdates) {
		t.Fatalf("updates=%d, want %d", len(backend.updates), len(wantUpdates))
	}
	for i, want := range wantUpdates {
		if backend.updates[i] != want {
			t.Fatalf("update[%d]=%p, want %p", i, backend.updates[i], want)
		}
	}
	group := set.groups[testTCHookSpec(1, old1).key().group]
	if group.entries[1].spec.Program != old1 || group.entries[2].spec.Program != old2 {
		t.Fatal("partial TCX update did not restore both old programs")
	}
}

func TestTCHookSetFallsBackToSameHandleClassicReplace(t *testing.T) {
	backend := &fakeTCHookBackend{attachErr: ciliumLink.ErrNotSupported}
	set := newTCHookSetWithBackend(logrus.New(), backend.moduleBackend())
	oldProgram, newProgram := new(ebpf.Program), new(ebpf.Program)
	oldSpec := testTCHookSpec(1, oldProgram)
	newSpec := testTCHookSpec(1, newProgram)

	if err := set.beginReplace(); err != nil {
		t.Fatal(err)
	}
	_ = set.stage(oldSpec)
	if err := set.commit(); err != nil {
		t.Fatal(err)
	}
	set.finalize()

	if err := set.beginReplace(); err != nil {
		t.Fatal(err)
	}
	_ = set.stage(newSpec)
	if err := set.commit(); err != nil {
		t.Fatal(err)
	}
	if err := set.rollback(); err != nil {
		t.Fatal(err)
	}

	if len(backend.classicReplaces) != 3 {
		t.Fatalf("classic replaces=%d, want initial/update/rollback", len(backend.classicReplaces))
	}
	for i, replaced := range backend.classicReplaces {
		if replaced.spec.Handle != oldSpec.Handle {
			t.Fatalf("replace[%d] handle=%#x, want stable %#x", i, replaced.spec.Handle, oldSpec.Handle)
		}
	}
	if backend.classicReplaces[0].spec.Program != oldProgram || backend.classicReplaces[1].spec.Program != newProgram || backend.classicReplaces[2].spec.Program != oldProgram {
		t.Fatal("classic replace sequence did not preserve rollback program")
	}
}

func TestTCHookSetPreservesExistingClassicFilterOrdering(t *testing.T) {
	backend := &fakeTCHookBackend{classicFiltersPresent: true}
	set := newTCHookSetWithBackend(logrus.New(), backend.moduleBackend())
	if err := set.beginReplace(); err != nil {
		t.Fatal(err)
	}
	_ = set.stage(testTCHookSpec(1, new(ebpf.Program)))
	if err := set.commit(); err != nil {
		t.Fatal(err)
	}
	if len(backend.attachments) != 0 || len(backend.classicReplaces) != 1 {
		t.Fatalf("TCX attaches/classic replaces=%d/%d, want 0/1", len(backend.attachments), len(backend.classicReplaces))
	}
}

func TestTCHookSetDoesNotHideClassicFilterInspectionError(t *testing.T) {
	wantErr := stderrors.New("filter list rejected")
	backend := &fakeTCHookBackend{classicFilterInspectErr: wantErr}
	set := newTCHookSetWithBackend(logrus.New(), backend.moduleBackend())
	if err := set.beginReplace(); err != nil {
		t.Fatal(err)
	}
	_ = set.stage(testTCHookSpec(1, new(ebpf.Program)))
	if err := set.commit(); !stderrors.Is(err, wantErr) {
		t.Fatalf("commit error=%v, want %v", err, wantErr)
	}
	if len(backend.attachments) != 0 || len(backend.classicReplaces) != 0 {
		t.Fatal("filter inspection failure incorrectly selected an attachment adapter")
	}
}

func TestTCHookSetDoesNotFallbackOnOperationalTCXError(t *testing.T) {
	wantErr := stderrors.New("tcx attach rejected")
	backend := &fakeTCHookBackend{attachErr: wantErr}
	set := newTCHookSetWithBackend(logrus.New(), backend.moduleBackend())

	if err := set.beginReplace(); err != nil {
		t.Fatal(err)
	}
	_ = set.stage(testTCHookSpec(1, new(ebpf.Program)))
	if err := set.commit(); !stderrors.Is(err, wantErr) {
		t.Fatalf("commit error = %v, want %v", err, wantErr)
	}
	if len(backend.classicReplaces) != 0 {
		t.Fatal("operational TCX failure incorrectly selected classic fallback")
	}
}

func TestTCHookSetUpdateErrorForcesTCXRollback(t *testing.T) {
	oldProgram, newProgram := new(ebpf.Program), new(ebpf.Program)
	backend := &fakeTCHookBackend{
		updateErr:              stderrors.New("update ACK failed"),
		failUpdateProgram:      newProgram,
		applyUpdateBeforeError: true,
	}
	set := newTCHookSetWithBackend(logrus.New(), backend.moduleBackend())
	if err := set.beginReplace(); err != nil {
		t.Fatal(err)
	}
	_ = set.stage(testTCHookSpec(1, oldProgram))
	if err := set.commit(); err != nil {
		t.Fatal(err)
	}
	set.finalize()

	if err := set.beginReplace(); err != nil {
		t.Fatal(err)
	}
	_ = set.stage(testTCHookSpec(1, newProgram))
	if err := set.commit(); !stderrors.Is(err, backend.updateErr) {
		t.Fatalf("commit error=%v, want %v", err, backend.updateErr)
	}
	if len(backend.updates) != 2 || backend.updates[0] != newProgram || backend.updates[1] != oldProgram {
		t.Fatalf("TCX update sequence=%v, want new then old", backend.updates)
	}
	if backend.attachments[0].hook.program != oldProgram {
		t.Fatal("TCX rollback did not restore old program after post-side-effect error")
	}
}

func TestTCHookSetReplaceErrorForcesClassicRollback(t *testing.T) {
	oldProgram, newProgram := new(ebpf.Program), new(ebpf.Program)
	backend := &fakeTCHookBackend{attachErr: ciliumLink.ErrNotSupported}
	set := newTCHookSetWithBackend(logrus.New(), backend.moduleBackend())
	if err := set.beginReplace(); err != nil {
		t.Fatal(err)
	}
	_ = set.stage(testTCHookSpec(1, oldProgram))
	if err := set.commit(); err != nil {
		t.Fatal(err)
	}
	set.finalize()

	backend.failReplaceProgram = newProgram
	backend.replaceErr = stderrors.New("replace ACK failed")
	if err := set.beginReplace(); err != nil {
		t.Fatal(err)
	}
	_ = set.stage(testTCHookSpec(1, newProgram))
	if err := set.commit(); !stderrors.Is(err, backend.replaceErr) {
		t.Fatalf("commit error=%v, want %v", err, backend.replaceErr)
	}
	if len(backend.classicReplaces) != 3 {
		t.Fatalf("classic replaces=%d, want old/new/old", len(backend.classicReplaces))
	}
	if backend.classicReplaces[2].spec.Program != oldProgram {
		t.Fatal("classic rollback did not replace uncertain program with snapshot")
	}
}

func TestTCHookSetDetachErrorForcesReattach(t *testing.T) {
	oldProgram := new(ebpf.Program)
	backend := &fakeTCHookBackend{}
	set := newTCHookSetWithBackend(logrus.New(), backend.moduleBackend())
	if err := set.beginReplace(); err != nil {
		t.Fatal(err)
	}
	_ = set.stage(testTCHookSpec(1, oldProgram))
	if err := set.commit(); err != nil {
		t.Fatal(err)
	}
	set.finalize()

	wantErr := stderrors.New("close reported after detach")
	backend.closeErr = wantErr
	if err := set.beginReplace(); err != nil {
		t.Fatal(err)
	}
	if err := set.commit(); !stderrors.Is(err, wantErr) {
		t.Fatalf("commit error=%v, want %v", err, wantErr)
	}
	if len(backend.attachments) != 2 {
		t.Fatalf("TCX attachments=%d, want original plus rollback reattach", len(backend.attachments))
	}
	if !backend.attachments[0].hook.closed || backend.attachments[1].hook.program != oldProgram {
		t.Fatal("rollback did not reattach snapshot after uncertain close")
	}
}

func TestTCHookSetDynamicDualRoleCallbacksAreIdempotent(t *testing.T) {
	backend := &fakeTCHookBackend{}
	set := newTCHookSetWithBackend(logrus.New(), backend.moduleBackend())
	ingress := testTCHookSpec(1, new(ebpf.Program))
	egress := ingress
	egress.Direction = tcHookEgress
	egress.Name = "test-egress"

	for _, spec := range []tcHookSpec{ingress, egress, ingress, egress} {
		if err := set.upsert(spec); err != nil {
			t.Fatal(err)
		}
	}
	if len(backend.attachments) != 2 {
		t.Fatalf("initial attachments=%d, want one per direction", len(backend.attachments))
	}
	if err := set.removeInterface(tcHookScopeHost, ingress.Ifindex); err != nil {
		t.Fatal(err)
	}
	if err := set.removeInterface(tcHookScopeHost, ingress.Ifindex); err != nil {
		t.Fatal(err)
	}
	for _, spec := range []tcHookSpec{ingress, egress, ingress, egress} {
		if err := set.upsert(spec); err != nil {
			t.Fatal(err)
		}
	}
	if len(backend.attachments) != 4 {
		t.Fatalf("attachments after recreation=%d, want exactly two new links", len(backend.attachments))
	}
	if len(set.groups) != 2 {
		t.Fatalf("groups after recreation=%d, want ingress and egress", len(set.groups))
	}

	stagedBackend := &fakeTCHookBackend{}
	staged := newTCHookSetWithBackend(logrus.New(), stagedBackend.moduleBackend())
	if err := staged.beginReplace(); err != nil {
		t.Fatal(err)
	}
	_ = staged.stage(ingress)
	_ = staged.stage(egress)
	if err := staged.stageRemoveInterface(tcHookScopeHost, ingress.Ifindex); err != nil {
		t.Fatal(err)
	}
	if err := staged.stageRemoveInterface(tcHookScopeHost, ingress.Ifindex); err != nil {
		t.Fatal(err)
	}
	_ = staged.stage(ingress)
	_ = staged.stage(egress)
	_ = staged.stage(ingress)
	_ = staged.stage(egress)
	if err := staged.commit(); err != nil {
		t.Fatal(err)
	}
	staged.finalize()
	if len(stagedBackend.attachments) != 2 {
		t.Fatalf("staged recreation attachments=%d, want one per direction", len(stagedBackend.attachments))
	}
}

func TestTCHookHandoffTransfersCloseOwnership(t *testing.T) {
	backend := &fakeTCHookBackend{}
	active := newTCHookSetWithBackend(logrus.New(), backend.moduleBackend())
	if err := active.beginReplace(); err != nil {
		t.Fatal(err)
	}
	_ = active.stage(testTCHookSpec(1, new(ebpf.Program)))
	if err := active.commit(); err != nil {
		t.Fatal(err)
	}
	active.finalize()

	previous := &controlPlaneCore{log: logrus.New(), tcHooks: active}
	candidate := &controlPlaneCore{log: logrus.New(), tcHooks: newTCHookSetWithBackend(logrus.New(), backend.moduleBackend())}
	if err := candidate.prepareTCHookHandoff(previous); err != nil {
		t.Fatal(err)
	}
	if err := candidate.beginTCHookReplace(); err != nil {
		t.Fatal(err)
	}
	_ = candidate.stageTCHook(testTCHookSpec(1, new(ebpf.Program)))
	if err := candidate.commitTCHookReplace(); err != nil {
		t.Fatal(err)
	}
	if err := candidate.adoptPreparedTCHookSet(previous); err != nil {
		t.Fatal(err)
	}
	if err := candidate.finalizePreparedTCHooks(); err != nil {
		t.Fatal(err)
	}

	if err := previous.closeOwnedTCHookSet(); err != nil {
		t.Fatal(err)
	}
	if backend.closed != 0 {
		t.Fatalf("previous owner detached transferred TCX link: closes=%d", backend.closed)
	}
	if err := candidate.closeOwnedTCHookSet(); err != nil {
		t.Fatal(err)
	}
	if backend.closed != 1 {
		t.Fatalf("candidate close count=%d, want 1", backend.closed)
	}
}

func TestTCHookHandoffRestoresOwnershipBeforeRollback(t *testing.T) {
	backend := &fakeTCHookBackend{}
	oldProgram, newProgram := new(ebpf.Program), new(ebpf.Program)
	active := newTCHookSetWithBackend(logrus.New(), backend.moduleBackend())
	if err := active.beginReplace(); err != nil {
		t.Fatal(err)
	}
	_ = active.stage(testTCHookSpec(1, oldProgram))
	if err := active.commit(); err != nil {
		t.Fatal(err)
	}
	active.finalize()

	previous := &controlPlaneCore{log: logrus.New(), tcHooks: active}
	candidate := &controlPlaneCore{log: logrus.New(), tcHooks: newTCHookSetWithBackend(logrus.New(), backend.moduleBackend())}
	if err := candidate.prepareTCHookHandoff(previous); err != nil {
		t.Fatal(err)
	}
	if err := candidate.beginTCHookReplace(); err != nil {
		t.Fatal(err)
	}
	_ = candidate.stageTCHook(testTCHookSpec(1, newProgram))
	if err := candidate.commitTCHookReplace(); err != nil {
		t.Fatal(err)
	}
	if err := candidate.adoptPreparedTCHookSet(previous); err != nil {
		t.Fatal(err)
	}
	if err := candidate.restorePreparedTCHookSet(previous); err != nil {
		t.Fatal(err)
	}
	if err := candidate.rollbackPreparedTCHooks(); err != nil {
		t.Fatal(err)
	}
	if err := candidate.clearPreparedTCHookHandoff(); err != nil {
		t.Fatal(err)
	}

	if previous.ownedTCHookSet() != active {
		t.Fatal("rollback did not return active HookSet to previous generation")
	}
	group := active.groups[testTCHookSpec(1, oldProgram).key().group]
	if group.entries[1].spec.Program != oldProgram {
		t.Fatal("rollback did not restore previous TCX program")
	}
	if err := candidate.closeOwnedTCHookSet(); err != nil {
		t.Fatal(err)
	}
	if backend.closed != 0 {
		t.Fatal("discarded candidate detached previous generation TCX link")
	}
}

func TestTCHookPatternsDetectOnlyDualRoleInterfaces(t *testing.T) {
	core := &controlPlaneCore{}
	core.configureTCHookPatterns([]string{"lan*", "shared0"}, []string{"wan*", "shared*"})

	for _, ifname := range []string{"shared0"} {
		if !core.isDualRoleTCInterface(ifname) {
			t.Fatalf("interface %q was not detected as dual-role", ifname)
		}
	}
	for _, ifname := range []string{"lan0", "wan0", "other0"} {
		if core.isDualRoleTCInterface(ifname) {
			t.Fatalf("single-role interface %q was detected as dual-role", ifname)
		}
	}
}

func TestDualRoleTCHookProgramsUseOneCompositePerDirection(t *testing.T) {
	l2Ingress, l2Egress := new(ebpf.Program), new(ebpf.Program)
	l3Ingress, l3Egress := new(ebpf.Program), new(ebpf.Program)
	objects := &bpfObjects{bpfPrograms: bpfPrograms{
		TproxyWanLanIngressL2: l2Ingress,
		TproxyWanLanIngressL3: l3Ingress,
		TproxyLanWanEgressL2:  l2Egress,
		TproxyLanWanEgressL3:  l3Egress,
	}}

	layer2 := selectDualRoleTCHookPrograms(objects, true)
	if layer2.ingress != l2Ingress || layer2.egress != l2Egress {
		t.Fatal("layer-2 dual-role hooks did not select composite programs")
	}
	layer3 := selectDualRoleTCHookPrograms(objects, false)
	if layer3.ingress != l3Ingress || layer3.egress != l3Egress {
		t.Fatal("layer-3 dual-role hooks did not select composite programs")
	}
}
