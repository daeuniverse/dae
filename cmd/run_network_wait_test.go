/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func discardLogger() *logrus.Logger {
	log := logrus.New()
	log.SetOutput(io.Discard)
	return log
}

// TestWaitForNetworkOnlineSucceedsOnFirstLink pins the happy path: a reachable
// check link ends the wait on the first attempt.
func TestWaitForNetworkOnlineSucceedsOnFirstLink(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	attempts, online, err := waitForNetworkOnline(context.Background(), srv.Client(), discardLogger(), []string{srv.URL}, 10*time.Millisecond, time.Second)
	if err != nil {
		t.Fatalf("waitForNetworkOnline: %v", err)
	}
	if !online || attempts != 1 {
		t.Fatalf("online=%v attempts=%d, want true/1", online, attempts)
	}
}

// TestWaitForNetworkOnlineCountsClientErrorsAsOnline keeps the original
// semantics: a 4xx answer (captive portal, redirecting middlebox) still proves
// the interface has connectivity.
func TestWaitForNetworkOnlineCountsClientErrorsAsOnline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	attempts, online, err := waitForNetworkOnline(context.Background(), srv.Client(), discardLogger(), []string{srv.URL}, 10*time.Millisecond, time.Second)
	if err != nil || !online || attempts != 1 {
		t.Fatalf("online=%v attempts=%d err=%v, want true/1/nil", online, attempts, err)
	}
}

// TestWaitForNetworkOnlineRetriesBadStatusThenSucceeds covers a link that fails
// before the network is up.
func TestWaitForNetworkOnlineRetriesBadStatusThenSucceeds(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	attempts, online, err := waitForNetworkOnline(context.Background(), srv.Client(), discardLogger(), []string{srv.URL}, 10*time.Millisecond, time.Second)
	if err != nil || !online || attempts != 2 {
		t.Fatalf("online=%v attempts=%d err=%v, want true/2/nil", online, attempts, err)
	}
}

// TestWaitForNetworkOnlineIsBounded is the regression for the startup hang: an
// unreachable network must end the wait after the bound instead of looping
// forever, and it must not be reported as an error (the subscription stage
// reports the real cause).
func TestWaitForNetworkOnlineIsBounded(t *testing.T) {
	// A port that is closed: every request fails immediately.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()

	timeout := 150 * time.Millisecond
	start := time.Now()
	attempts, online, err := waitForNetworkOnline(context.Background(), http.DefaultClient, discardLogger(), []string{url}, 20*time.Millisecond, timeout)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("an unreachable network must not be fatal, got %v", err)
	}
	if online {
		t.Fatal("online must be false when every check fails")
	}
	if attempts == 0 {
		t.Fatal("the wait must have attempted at least one check")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("the wait took %v; it is not bounded by %v", elapsed, timeout)
	}
}

// TestWaitForNetworkOnlineHonoursContext makes sure a cancelled run (shutdown,
// reload deadline) ends the wait immediately with the context error.
func TestWaitForNetworkOnlineHonoursContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	attempts, online, err := waitForNetworkOnline(ctx, srv.Client(), discardLogger(), []string{srv.URL}, time.Second, time.Minute)
	if err != context.Canceled {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if online || attempts != 0 {
		t.Fatalf("online=%v attempts=%d, want false/0", online, attempts)
	}
}

// roundTripFunc adapts a function to an http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestWaitForNetworkOnlineCancelsInFlightRequest pins that cancellation
// interrupts a request that is already running. The call uses an hour-long
// interval and timeout, so only an interrupted request can end it promptly; a
// client.Get that ignores the context would leave this test hanging.
func TestWaitForNetworkOnlineCancelsInFlightRequest(t *testing.T) {
	started := make(chan struct{}, 4)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case started <- struct{}{}:
		default:
		}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()
	defer close(release)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		_, _, err := waitForNetworkOnline(ctx, srv.Client(), discardLogger(), []string{srv.URL}, time.Hour, time.Hour)
		errCh <- err
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the first request never reached the server")
	}
	cancel()
	select {
	case err := <-errCh:
		if err != context.Canceled {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation did not interrupt the in-flight request")
	}
}

// TestWaitForNetworkOnlineWaitsBetweenFailures pins that an instant failure
// still consumes the retry interval: a request that fails in microseconds must
// not turn the wait into a busy spin against a dead link.
func TestWaitForNetworkOnlineWaitsBetweenFailures(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("link down")
	})}
	const interval = 20 * time.Millisecond
	start := time.Now()
	attempts, online, err := waitForNetworkOnline(context.Background(), client, discardLogger(),
		[]string{"http://link.invalid/"}, interval, 120*time.Millisecond)
	if err != nil || online {
		t.Fatalf("attempts=%d online=%v err=%v, want a bounded offline result", attempts, online, err)
	}
	if maxAttempts := 12; attempts > maxAttempts {
		t.Fatalf("attempts = %d in %v; the loop busy-spins instead of waiting %v between attempts",
			attempts, time.Since(start), interval)
	}
}
