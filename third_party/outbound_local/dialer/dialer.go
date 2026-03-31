package dialer

import (
	"fmt"
	"time"
)

var (
	UnexpectedFieldErr  = fmt.Errorf("unexpected field")   // nolint:staticcheck
	InvalidParameterErr = fmt.Errorf("invalid parameters") // nolint:staticcheck
)

type ExtraOption struct {
	AllowInsecure       bool
	TlsImplementation   string
	TlsFragment         bool
	TlsFragmentLength   string
	TlsFragmentInterval string
	UtlsImitate         string
	BandwidthMaxTx      string
	BandwidthMaxRx      string
	UDPHopInterval      time.Duration
}

type Property struct {
	Name     string
	Address  string
	Protocol string
	Link     string
}
