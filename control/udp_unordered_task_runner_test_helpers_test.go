package control

import "context"

func newUdpUnorderedTaskRunner(ctx context.Context, workers, queueSizePerWorker int) *udpUnorderedTaskRunner {
	return newUdpUnorderedTaskRunnerWithOverflow(ctx, workers, queueSizePerWorker, 0, 0)
}
