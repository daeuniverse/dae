package control

import (
	stderrors "errors"
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	ciliumLink "github.com/cilium/ebpf/link"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestTCHookSetKernelUpdateAndRollback(t *testing.T) {
	oldProgram := newKernelTCHookTestProgram(t, "dae_tc_old", 0)
	t.Cleanup(func() {
		if err := oldProgram.Close(); err != nil {
			t.Errorf("close old TC program: %v", err)
		}
	})
	newProgram := newKernelTCHookTestProgram(t, "dae_tc_new", 2)
	t.Cleanup(func() {
		if err := newProgram.Close(); err != nil {
			t.Errorf("close new TC program: %v", err)
		}
	})

	name := fmt.Sprintf("daehs%x", os.Getpid()&0xffff)
	peerName := fmt.Sprintf("daehp%x", os.Getpid()&0xffff)
	attrs := netlink.NewLinkAttrs()
	attrs.Name = name
	veth := &netlink.Veth{LinkAttrs: attrs, PeerName: peerName}
	if err := netlink.LinkAdd(veth); err != nil {
		if stderrors.Is(err, unix.EPERM) || stderrors.Is(err, unix.EACCES) {
			t.Skipf("creating veth requires CAP_NET_ADMIN: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := netlink.LinkDel(veth); err != nil && !stderrors.Is(err, unix.ENODEV) {
			t.Errorf("delete TC test veth: %v", err)
		}
	})
	link, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.QdiscAdd(buildClsactQdisc(link)); err != nil && !stderrors.Is(err, unix.EEXIST) {
		t.Fatal(err)
	}

	t.Run("tcx", func(t *testing.T) {
		set := newTCHookSet(logrus.New())
		t.Cleanup(func() { _ = set.close() })
		oldSpec := makeTCHookSpec(tcHookScopeHost, link, tcHookIngress, 1, 0x2023, oldProgram, "dae_tcx_old", nil)
		newSpec := makeTCHookSpec(tcHookScopeHost, link, tcHookIngress, 1, 0x2023, newProgram, "dae_tcx_new", nil)
		if err := set.beginReplace(); err != nil {
			t.Fatal(err)
		}
		_ = set.stage(oldSpec)
		if err := set.commit(); err != nil {
			t.Fatal(err)
		}
		group := set.groups[oldSpec.key().group]
		if group.mode == tcHookModeClassic {
			_ = set.rollback()
			t.Skip("TCX is not supported by this kernel")
		}
		set.finalize()
		assertTCXProgramAttached(t, link.Attrs().Index, kernelProgramID(t, oldProgram))

		if err := set.beginReplace(); err != nil {
			t.Fatal(err)
		}
		_ = set.stage(newSpec)
		if err := set.commit(); err != nil {
			t.Fatal(err)
		}
		assertTCXProgramAttached(t, link.Attrs().Index, kernelProgramID(t, newProgram))
		if err := set.rollback(); err != nil {
			t.Fatal(err)
		}
		assertTCXProgramAttached(t, link.Attrs().Index, kernelProgramID(t, oldProgram))
		if err := set.close(); err != nil {
			t.Fatal(err)
		}
		assertTCXProgramAbsent(t, link.Attrs().Index, kernelProgramID(t, oldProgram))
	})

	t.Run("classic", func(t *testing.T) {
		backend := newRealTCHookBackend()
		backend.attachTCX = func(tcHookSpec, tcxHookPosition) (tcxHookAttachment, error) {
			return nil, ciliumLink.ErrNotSupported
		}
		set := newTCHookSetWithBackend(logrus.New(), backend)
		t.Cleanup(func() { _ = set.close() })
		oldSpec := makeTCHookSpec(tcHookScopeHost, link, tcHookEgress, 1, 0x2023, oldProgram, "dae_cls_old", nil)
		newSpec := makeTCHookSpec(tcHookScopeHost, link, tcHookEgress, 1, 0x2023, newProgram, "dae_cls_new", nil)
		if err := set.beginReplace(); err != nil {
			t.Fatal(err)
		}
		_ = set.stage(oldSpec)
		if err := set.commit(); err != nil {
			t.Fatal(err)
		}
		set.finalize()
		assertClassicTCProgram(t, link, oldSpec, kernelProgramID(t, oldProgram))

		if err := set.beginReplace(); err != nil {
			t.Fatal(err)
		}
		_ = set.stage(newSpec)
		if err := set.commit(); err != nil {
			t.Fatal(err)
		}
		assertClassicTCProgram(t, link, newSpec, kernelProgramID(t, newProgram))
		if err := set.rollback(); err != nil {
			t.Fatal(err)
		}
		assertClassicTCProgram(t, link, oldSpec, kernelProgramID(t, oldProgram))
		if err := set.close(); err != nil {
			t.Fatal(err)
		}
		filters, err := netlink.FilterList(link, oldSpec.parent())
		if err != nil {
			t.Fatal(err)
		}
		for _, filter := range filters {
			if filter.Attrs().Handle == oldSpec.Handle {
				t.Fatalf("classic filter handle %#x remained after close", oldSpec.Handle)
			}
		}
	})

	t.Run("classic_coexistence", func(t *testing.T) {
		external := &netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_MIN_INGRESS,
				Handle:    netlink.MakeHandle(0x4040, 2),
				Protocol:  unix.ETH_P_ALL,
				Priority:  10,
			},
			Fd:           oldProgram.FD(),
			Name:         "external_test",
			DirectAction: true,
		}
		if err := netlink.FilterReplace(external); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = netlink.FilterDel(external) })

		set := newTCHookSet(logrus.New())
		t.Cleanup(func() { _ = set.close() })
		spec := makeTCHookSpec(tcHookScopeHost, link, tcHookIngress, 1, 0x2023, oldProgram, "dae_tc_old", nil)
		if err := set.beginReplace(); err != nil {
			t.Fatal(err)
		}
		_ = set.stage(spec)
		if err := set.commit(); err != nil {
			t.Fatal(err)
		}
		group := set.groups[spec.key().group]
		if group.mode != tcHookModeClassic {
			t.Fatalf("mode=%v, want classic while another classic filter exists", group.mode)
		}
		set.finalize()
		if err := set.close(); err != nil {
			t.Fatal(err)
		}
		filters, err := netlink.FilterList(link, spec.parent())
		if err != nil {
			t.Fatal(err)
		}
		foundExternal := false
		for _, filter := range filters {
			if filter.Attrs().Handle == external.Handle {
				foundExternal = true
			}
			if filter.Attrs().Handle == spec.Handle {
				t.Fatalf("dae filter handle %#x remained after close", spec.Handle)
			}
		}
		if !foundExternal {
			t.Fatal("closing dae HookSet removed third-party classic filter")
		}
	})

	t.Run("continuation", testTCHookContinuationOnPacketPath)
}

func testTCHookContinuationOnPacketPath(t *testing.T) {
	continueProgram := newKernelTCHookTestProgram(t, "dae_tc_next", -1)
	t.Cleanup(func() {
		if err := continueProgram.Close(); err != nil {
			t.Errorf("close continuation TC program: %v", err)
		}
	})
	dropProgram := newKernelTCHookTestProgram(t, "dae_tc_drop", 2)
	t.Cleanup(func() {
		if err := dropProgram.Close(); err != nil {
			t.Errorf("close drop TC program: %v", err)
		}
	})

	nsName := fmt.Sprintf("dae-tc-%x", os.Getpid()&0xffff)
	hostName := fmt.Sprintf("daetch%x", os.Getpid()&0xffff)
	peerName := fmt.Sprintf("daetcp%x", os.Getpid()&0xffff)
	_ = runKernelTCHookIP("link", "del", hostName)
	_ = runKernelTCHookIP("netns", "del", nsName)
	if err := runKernelTCHookIP("netns", "add", nsName); err != nil {
		t.Skipf("creating network namespace requires CAP_SYS_ADMIN: %v", err)
	}
	t.Cleanup(func() {
		_ = runKernelTCHookIP("link", "del", hostName)
		_ = runKernelTCHookIP("netns", "del", nsName)
	})
	commands := [][]string{
		{"link", "add", hostName, "type", "veth", "peer", "name", peerName},
		{"link", "set", peerName, "netns", nsName},
		{"addr", "add", "10.204.0.1/30", "dev", hostName},
		{"link", "set", hostName, "up"},
		{"netns", "exec", nsName, "ip", "addr", "add", "10.204.0.2/30", "dev", peerName},
		{"netns", "exec", nsName, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", nsName, "ip", "link", "set", peerName, "up"},
	}
	for _, command := range commands {
		if err := runKernelTCHookIP(command...); err != nil {
			t.Fatal(err)
		}
	}
	link, err := netlink.LinkByName(hostName)
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.QdiscAdd(buildClsactQdisc(link)); err != nil && !stderrors.Is(err, unix.EEXIST) {
		t.Fatal(err)
	}
	assertKernelTCHookPing(t, nsName, true)

	continueSpec := makeTCHookSpec(tcHookScopeHost, link, tcHookIngress, 1, 0x2023, continueProgram, "dae_tc_next", nil)
	dropSpec := makeTCHookSpec(tcHookScopeHost, link, tcHookIngress, 2, 0x2023, dropProgram, "dae_tc_drop", nil)

	t.Run("tcx", func(t *testing.T) {
		set := newTCHookSet(logrus.New())
		t.Cleanup(func() { _ = set.close() })
		if err := set.beginReplace(); err != nil {
			t.Fatal(err)
		}
		_ = set.stage(continueSpec)
		_ = set.stage(dropSpec)
		if err := set.commit(); err != nil {
			t.Fatal(err)
		}
		group := set.groups[continueSpec.key().group]
		if group.mode == tcHookModeClassic {
			_ = set.rollback()
			t.Skip("TCX is not supported by this kernel")
		}
		set.finalize()
		assertKernelTCHookPing(t, nsName, false)
		if err := set.close(); err != nil {
			t.Fatal(err)
		}
		assertKernelTCHookPing(t, nsName, true)
	})

	t.Run("classic", func(t *testing.T) {
		backend := newRealTCHookBackend()
		backend.attachTCX = func(tcHookSpec, tcxHookPosition) (tcxHookAttachment, error) {
			return nil, ciliumLink.ErrNotSupported
		}
		set := newTCHookSetWithBackend(logrus.New(), backend)
		t.Cleanup(func() { _ = set.close() })
		if err := set.beginReplace(); err != nil {
			t.Fatal(err)
		}
		_ = set.stage(continueSpec)
		_ = set.stage(dropSpec)
		if err := set.commit(); err != nil {
			t.Fatal(err)
		}
		set.finalize()
		assertKernelTCHookPing(t, nsName, false)
		if err := set.close(); err != nil {
			t.Fatal(err)
		}
		assertKernelTCHookPing(t, nsName, true)
	})
}

func runKernelTCHookIP(args ...string) error {
	output, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %v: %w: %s", args, err, output)
	}
	return nil
}

func assertKernelTCHookPing(t *testing.T, nsName string, shouldPass bool) {
	t.Helper()
	command := exec.Command("ip", "netns", "exec", nsName, "ping", "-q", "-c", "1", "-W", "1", "10.204.0.1")
	err := command.Run()
	if shouldPass && err != nil {
		t.Fatalf("packet did not pass TC chain: %v", err)
	}
	if !shouldPass && err == nil {
		t.Fatal("packet bypassed lower-priority TC drop program")
	}
}

func newKernelTCHookTestProgram(t *testing.T, name string, result int32) *ebpf.Program {
	t.Helper()
	program, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: name,
		Type: ebpf.SchedCLS,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, result),
			asm.Return(),
		},
		License: "GPL",
	})
	if err != nil {
		if stderrors.Is(err, unix.EPERM) || stderrors.Is(err, unix.EACCES) {
			t.Skipf("loading TC program requires BPF privileges: %v", err)
		}
		t.Fatal(err)
	}
	return program
}

func kernelProgramID(t *testing.T, program *ebpf.Program) ebpf.ProgramID {
	t.Helper()
	info, err := program.Info()
	if err != nil {
		t.Fatal(err)
	}
	id, ok := info.ID()
	if !ok {
		t.Fatal("kernel did not report program ID")
	}
	return id
}

func assertTCXProgramAttached(t *testing.T, ifindex int, want ebpf.ProgramID) {
	t.Helper()
	result, err := ciliumLink.QueryPrograms(ciliumLink.QueryOptions{Target: ifindex, Attach: ebpf.AttachTCXIngress})
	if err != nil {
		t.Fatal(err)
	}
	for _, attached := range result.Programs {
		if attached.ID == want {
			return
		}
	}
	t.Fatalf("TCX program %d is not attached; programs=%v", want, result.Programs)
}

func assertTCXProgramAbsent(t *testing.T, ifindex int, want ebpf.ProgramID) {
	t.Helper()
	result, err := ciliumLink.QueryPrograms(ciliumLink.QueryOptions{Target: ifindex, Attach: ebpf.AttachTCXIngress})
	if err != nil {
		t.Fatal(err)
	}
	for _, attached := range result.Programs {
		if attached.ID == want {
			t.Fatalf("TCX program %d remained attached", want)
		}
	}
}

func assertClassicTCProgram(t *testing.T, link netlink.Link, spec tcHookSpec, want ebpf.ProgramID) {
	t.Helper()
	filters, err := netlink.FilterList(link, spec.parent())
	if err != nil {
		t.Fatal(err)
	}
	matches := 0
	for _, filter := range filters {
		if filter.Attrs().Handle != spec.Handle {
			continue
		}
		matches++
		bpfFilter, ok := filter.(*netlink.BpfFilter)
		if !ok {
			t.Fatalf("filter type %T, want *netlink.BpfFilter", filter)
		}
		if ebpf.ProgramID(bpfFilter.Id) != want {
			t.Fatalf("classic program=%d, want %d", bpfFilter.Id, want)
		}
	}
	if matches != 1 {
		t.Fatalf("classic handle %#x matches=%d, want 1", spec.Handle, matches)
	}
}
