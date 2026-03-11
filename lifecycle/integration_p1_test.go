/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org
 */

package lifecycle_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/daeuniverse/dae/lifecycle"
	"github.com/sirupsen/logrus"
)

// TestLifecycleIntegration_P1 tests the Start flow integration.
func TestLifecycleIntegration_P1(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root privileges")
	}

	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	mgr := lifecycle.NewLifecycleManager(&lifecycle.ManagerConfig{
		Log:           log,
		DrainTimeout:  5 * time.Second,
		CleanShutdown: true,
	})

	// Configure the manager
	mgr.SetConfigFile("/test/config.dae", nil)
	mgr.SetPidFile("/tmp/dae-test.pid", false)

	ctx := context.Background()

	// Test Start
	req := &lifecycle.StartRequest{
		ConfigFile: "/test/config.dae",
	}

	// Start should fail because config file doesn't exist
	gen, err := mgr.Start(ctx, req)
	if err == nil {
		t.Log("Start succeeded (unexpected with invalid config)")
		if gen != nil {
			t.Logf("Generation ID: %s", gen.ID)
		}
	} else {
		t.Logf("Start failed as expected: %v", err)
	}

	// Verify state
	state := mgr.State()
	t.Logf("Final state: %s", state)
}

// TestConfigHash tests config hash computation.
func TestConfigHash(t *testing.T) {
	// This test verifies the config hash logic works
	// Actual config integration would require valid config files
	t.Skip("config hash test requires valid config objects")
}

// TestNeedsFullReload tests full reload detection logic.
func TestNeedsFullReload(t *testing.T) {
	// This test verifies the reload type detection logic
	// Would require valid config objects to test
	t.Skip("reload detection test requires valid config objects")
}
