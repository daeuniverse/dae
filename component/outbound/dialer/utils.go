package dialer

import "time"

func latencyString(latencyAfterOffset, latencyBeforeOffset time.Duration) string {
	if latencyBeforeOffset == latencyAfterOffset {
		return latencyAfterOffset.Truncate(time.Millisecond).String()
	}
	return latencyAfterOffset.Truncate(time.Millisecond).String() + "(" + latencyBeforeOffset.Truncate(time.Millisecond).String() + ")"
}
