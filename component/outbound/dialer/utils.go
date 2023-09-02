package dialer

import "time"

func latencyString(realLatency, latencyOffset time.Duration) string {
	var offsetSign string
	if latencyOffset > 0 {
		offsetSign = "+"
	} else {
		offsetSign = "-"
	}

	var offsetPart string
	if latencyOffset != 0 {
		offsetPart = "(" + offsetSign + latencyOffset.Truncate(time.Millisecond).Abs().String() + ")"
	} else { // latencyOffset == 0
		offsetPart = ""
	}

	return realLatency.Truncate(time.Millisecond).String() + offsetPart
}
