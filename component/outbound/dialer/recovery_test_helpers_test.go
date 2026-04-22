package dialer

import (
	"time"

	"github.com/daeuniverse/dae/common/consts"
)

func (d *Dialer) getRecoveryBackoffDuration(proto consts.L4ProtoStr) time.Duration {
	return d.getRecoveryBackoffDurationByIndex(d.protoIdx(proto))
}

func (d *Dialer) resetStabilityCount(proto consts.L4ProtoStr) {
	d.resetStabilityCountByIndex(d.protoIdx(proto))
}

func (d *Dialer) incrementBackoffLevel(proto consts.L4ProtoStr) {
	d.incrementBackoffLevelByIndex(d.protoIdx(proto))
}
