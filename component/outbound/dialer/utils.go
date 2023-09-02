package dialer

import "time"

func latencyString(realLatency, latencyOffset time.Duration) string {
	var offsetSign string = "+"
	if latencyOffset < 0 {
		offsetSign = "-"
	}

	var offsetPart string = ""
	if latencyOffset != 0 {
		offsetPart = "(" + offsetSign + latencyOffset.Truncate(time.Millisecond).Abs().String() + ")"
	}

	return realLatency.Truncate(time.Millisecond).String() + offsetPart
}
