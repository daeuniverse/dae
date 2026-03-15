package control

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestUdpUnorderedTaskRunner_BoundsConcurrency(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runner := newUdpUnorderedTaskRunner(ctx, 2, 32)

	var active atomic.Int32
	var maxActive atomic.Int32
	var done sync.WaitGroup

	const tasks = 32
	done.Add(tasks)
	for i := range tasks {
		key := UdpFlowKey{
			Src: netip.MustParseAddrPort("127.0.0.1:10000"),
			Dst: netip.MustParseAddrPort(netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(i + 1)}), 443).String()),
		}
		require.True(t, runner.Submit(key, func() {
			current := active.Add(1)
			for {
				seen := maxActive.Load()
				if current <= seen || maxActive.CompareAndSwap(seen, current) {
					break
				}
			}
			time.Sleep(10 * time.Millisecond)
			active.Add(-1)
			done.Done()
		}))
	}

	finished := make(chan struct{})
	go func() {
		done.Wait()
		close(finished)
	}()

	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for unordered tasks to finish")
	}

	require.EqualValues(t, 2, maxActive.Load(), "runner should never exceed worker count")
}

func TestUdpUnorderedTaskRunner_SubmitAfterCancelFails(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	runner := newUdpUnorderedTaskRunner(ctx, 1, 1)
	cancel()

	require.Eventually(t, func() bool {
		return !runner.Submit(UdpFlowKey{}, func() {})
	}, time.Second, 10*time.Millisecond)
}

func TestUdpUnorderedTaskRunner_SubmitWhenQueueFullFailsFast(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runner := newUdpUnorderedTaskRunner(ctx, 1, 1)
	started := make(chan struct{})
	release := make(chan struct{})

	require.True(t, runner.Submit(UdpFlowKey{Src: netip.MustParseAddrPort("127.0.0.1:10001")}, func() {
		close(started)
		<-release
	}))

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for worker to start first task")
	}

	require.True(t, runner.Submit(UdpFlowKey{Src: netip.MustParseAddrPort("127.0.0.1:10002")}, func() {}), "second task should fill the only queue slot")

	begin := time.Now()
	require.False(t, runner.Submit(UdpFlowKey{Src: netip.MustParseAddrPort("127.0.0.1:10003")}, func() {}), "third task should fail immediately when queue is full")
	if d := time.Since(begin); d > 50*time.Millisecond {
		t.Fatalf("queue-full Submit should fail fast, took %v", d)
	}

	close(release)
}

func TestUdpUnorderedTaskRunner_SubmitUsesOverflowWhenShardQueueFull(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runner := newUdpUnorderedTaskRunnerWithOverflow(ctx, 1, 1, 1, 1)
	shardStarted := make(chan struct{})
	shardRelease := make(chan struct{})
	overflowExecuted := make(chan struct{}, 1)

	require.True(t, runner.Submit(UdpFlowKey{Src: netip.MustParseAddrPort("127.0.0.1:11001")}, func() {
		close(shardStarted)
		<-shardRelease
	}))

	select {
	case <-shardStarted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for shard worker to start")
	}

	require.True(t, runner.Submit(UdpFlowKey{Src: netip.MustParseAddrPort("127.0.0.1:11002")}, func() {}), "second task should fill shard queue")
	require.True(t, runner.Submit(UdpFlowKey{Src: netip.MustParseAddrPort("127.0.0.1:11003")}, func() {
		overflowExecuted <- struct{}{}
	}), "third task should spill into overflow queue")

	select {
	case <-overflowExecuted:
	case <-time.After(time.Second):
		t.Fatal("overflow task was not executed while shard worker remained blocked")
	}

	close(shardRelease)
}

func TestUdpUnorderedTaskRunner_SubmitFailsWhenShardAndOverflowFull(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runner := newUdpUnorderedTaskRunnerWithOverflow(ctx, 1, 1, 1, 1)
	shardStarted := make(chan struct{})
	shardRelease := make(chan struct{})
	overflowStarted := make(chan struct{})
	overflowRelease := make(chan struct{})

	require.True(t, runner.Submit(UdpFlowKey{Src: netip.MustParseAddrPort("127.0.0.1:12001")}, func() {
		close(shardStarted)
		<-shardRelease
	}))
	select {
	case <-shardStarted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for shard worker to start")
	}

	require.True(t, runner.Submit(UdpFlowKey{Src: netip.MustParseAddrPort("127.0.0.1:12002")}, func() {}), "second task should fill shard queue")
	require.True(t, runner.Submit(UdpFlowKey{Src: netip.MustParseAddrPort("127.0.0.1:12003")}, func() {
		close(overflowStarted)
		<-overflowRelease
	}), "third task should occupy overflow worker")
	select {
	case <-overflowStarted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for overflow worker to start")
	}

	require.True(t, runner.Submit(UdpFlowKey{Src: netip.MustParseAddrPort("127.0.0.1:12004")}, func() {}), "fourth task should fill overflow queue")

	begin := time.Now()
	require.False(t, runner.Submit(UdpFlowKey{Src: netip.MustParseAddrPort("127.0.0.1:12005")}, func() {}), "fifth task should fail when shard and overflow are saturated")
	if d := time.Since(begin); d > 50*time.Millisecond {
		t.Fatalf("saturated Submit should fail fast, took %v", d)
	}

	close(overflowRelease)
	close(shardRelease)
}
