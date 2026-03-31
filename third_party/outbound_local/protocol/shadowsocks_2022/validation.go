package shadowsocks_2022

import (
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/protocol"
)

func validateTimestamp(timestamp time.Time, now time.Time) error {
	if timestamp.Before(now.Add(-ciphers.TimestampTolerance)) ||
		timestamp.After(now.Add(ciphers.TimestampTolerance)) {
		return protocol.ErrReplayAttack
	}
	return nil
}
