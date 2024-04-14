package dialer

type CheckResult struct {
	DialerProperty *Property
	Groups         []string
	CheckType      *NetworkType
	Latency        int64
	Alive          bool
	Err            error
}
