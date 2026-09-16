/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

// networkWaitTimeout bounds how long startup waits for the network before it
// continues without one. The machine may legitimately boot before its WAN
// interface is up, but an unreachable network must never stall dae forever:
// once the bound is reached the subscription stage runs and reports the real
// failure, so nodes declared directly in the config keep working.
const networkWaitTimeout = 5 * time.Minute

// getWithContext issues a context-aware GET so a cancelled startup wait
// interrupts an in-flight request instead of waiting for it to finish.
func getWithContext(ctx context.Context, client *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return client.Do(req)
}

// waitForNetworkOnline probes links in order until one answers with a status
// below 500, ctx is cancelled, or timeout elapses. A 2xx-4xx status counts as
// online because captive portals and redirecting middleboxes still prove that
// the interface has connectivity.
//
// It returns the number of attempts made and whether the network came online.
// Running out of time is not an error: the caller continues startup and lets
// the subscription stage report the actual cause, which keeps local nodes
// usable on a machine that never reaches the check links.
func waitForNetworkOnline(ctx context.Context, client *http.Client, log *logrus.Logger, links []string, interval, timeout time.Duration) (attempts int, online bool, err error) {
	if len(links) == 0 {
		return 0, false, errors.New("no network check link configured")
	}
	deadline := time.Now().Add(timeout)
	for i := 0; ; i++ {
		select {
		case <-ctx.Done():
			return attempts, false, ctx.Err()
		default:
		}

		if !time.Now().Before(deadline) {
			return attempts, false, nil
		}
		attempts++

		resp, gerr := getWithContext(ctx, client, links[i%len(links)])
		if gerr != nil {
			if log != nil {
				if attempts == 1 {
					log.Warnf("Network is not reachable yet (%v); retrying for up to %v.", gerr, timeout)
				} else {
					log.Debugln("CheckNetwork:", gerr)
				}
			}
			// Always wait before the next attempt: a request that fails
			// instantly (rather than consuming the retry interval, as a
			// timeout does) must not turn this loop into a busy spin.
			// NewTimer (unlike time.After) is stopped explicitly, so a
			// cancelled wait does not leave the timer registered until it
			// fires.
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return attempts, false, ctx.Err()
			case <-timer.C:
			}
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 500 {
			return attempts, true, nil
		}
		if log != nil {
			log.Infof("Bad status: %v (%v)", resp.Status, resp.StatusCode)
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return attempts, false, ctx.Err()
		case <-timer.C:
		}
	}
}
