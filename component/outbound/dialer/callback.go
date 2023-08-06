package dialer

type CheckResult struct {
	DialerProperty *Property
	CheckType      *NetworkType
	Latency        int64
	Alive          bool
	Err            error
}
