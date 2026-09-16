package dialer

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/sirupsen/logrus"
)

// newTestNetworkType returns a TCP/IPv4/DNS NetworkType used by dialer tests.
// Recovered from the pruned connectivity_check_test.go (Sprint 5 T1).
func newTestNetworkType() *NetworkType {
	return &NetworkType{
		L4Proto:   consts.L4ProtoStr_TCP,
		IpVersion: consts.IpVersionStr_4,
		IsDns:     true,
	}
}

// newNamedTestDialer builds a real Dialer backed by SymmetricDirect for tests.
// Recovered from the pruned connectivity_check_test.go (Sprint 5 T1).
func newNamedTestDialer(t *testing.T, name string) *Dialer {
	t.Helper()

	log := logrus.New()
	log.SetOutput(io.Discard)

	d := NewDialerContext(
		context.Background(),
		direct.SymmetricDirect,
		&GlobalOption{
			Log:            log,
			CheckInterval:  time.Minute,
			CheckTolerance: 0,
		},
		InstanceOption{},
		&Property{
			Property: D.Property{Name: name},
		},
	)
	t.Cleanup(func() {
		_ = d.Close()
	})
	return d
}
