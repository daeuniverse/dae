package logger

import (
	"testing"

	"gopkg.in/natefinch/lumberjack.v2"
)

func TestLogger(t *testing.T) {
	var logOpts *lumberjack.Logger
	log := NewLogger("debug", false, logOpts)
	log.Info("Hi there!")
}
