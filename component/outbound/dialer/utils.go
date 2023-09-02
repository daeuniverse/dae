package dialer

import "time"

func latencyString(realLatency, latencyOffset time.Duration) string {
	offsetPart := func() string {
		if latencyOffset > 0 {
			return "(+" + latencyOffset.Truncate(time.Millisecond).String() + ")"
		} else if latencyOffset < 0 {
			return "(" + latencyOffset.Truncate(time.Millisecond).String() + ")"
		} else { // latencyOffset == 0
			return ""
		}
	}()

	return realLatency.Truncate(time.Millisecond).String() + offsetPart
}
