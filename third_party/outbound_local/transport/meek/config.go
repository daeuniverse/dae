package meek

type config struct {
	MaxWriteSize             int32
	WaitSubsequentWriteMs    int32
	InitialPollingIntervalMs int32
	MaxPollingIntervalMs     int32
	MinPollingIntervalMs     int32
	BackoffFactor            float32
	FailedRetryIntervalMs    int32
}
