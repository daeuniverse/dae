package control

import (
	stderrors "errors"
	"slices"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestCommitPreparedBpfHookFlipDetachesPartialBindings(t *testing.T) {
	core := &controlPlaneCore{log: logrus.New()}
	plane := &ControlPlane{core: core}
	wantErr := stderrors.New("injected interface attach failure")
	var detachOrder []string

	err := plane.commitPreparedBpfHookFlip(func() error {
		if !core.addBpfHookDetach(func() error {
			detachOrder = append(detachOrder, "first")
			return nil
		}) {
			t.Fatal("first candidate hook was rejected before quiesce")
		}
		if !core.addBpfHookDetach(func() error {
			detachOrder = append(detachOrder, "second")
			return nil
		}) {
			t.Fatal("second candidate hook was rejected before quiesce")
		}
		return wantErr
	})
	if !stderrors.Is(err, wantErr) {
		t.Fatalf("commit error = %v, want injected failure", err)
	}
	if want := []string{"second", "first"}; !slices.Equal(detachOrder, want) {
		t.Fatalf("detach order = %v, want %v", detachOrder, want)
	}

	core.bpfHookMu.Lock()
	quiesced := core.bpfHooksQuiesced
	detached := core.bpfHooksDetached
	remaining := len(core.bpfHookDetachFuncs)
	core.bpfHookMu.Unlock()
	if !quiesced || !detached || remaining != 0 {
		t.Fatalf("partial hook cleanup: quiesced=%t detached=%t remaining=%d", quiesced, detached, remaining)
	}
}
