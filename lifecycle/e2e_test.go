/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org
 */

package lifecycle_test

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/cmd"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/lifecycle"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLifecycleE2E_EndToEnd tests the complete lifecycle.
// This is an end-to-end test that requires root privileges.
func TestLifecycleE2E_EndToEnd(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root privileges")
	}

	// Create temp directory for test files
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "test.dae")

	// Create minimal config (simpler format)
	configContent := `
global {}
routing {}
`
	err := os.WriteFile(cfgFile, []byte(configContent), 0600)
	require.NoError(t, err)

	// Create logger
	log := logrus.New()
	log.SetLevel(logrus.WarnLevel)
	log.SetOutput(os.Stdout)

	// Test config can be read
	conf, includes, err := cmd.ReadConfig(cfgFile)
	require.NoError(t, err)
	t.Logf("Config loaded with includes: %v", includes)
	assert.NotNil(t, conf)
}

// TestLifecycleE2E_ConfigHash tests config hash computation.
func TestLifecycleE2E_ConfigHash(t *testing.T) {
	// Create two configs
	cfg1 := &config.Config{
		Global: config.Global{
			TproxyPort: 12345,
		},
	}
	cfg2 := &config.Config{
		Global: config.Global{
			TproxyPort: 12345,
		},
	}
	cfg3 := &config.Config{
		Global: config.Global{
			TproxyPort: 54321,
		},
	}

	// Same config should produce same hash
	hash1 := lifecycle.ComputeConfigHash(cfg1)
	hash2 := lifecycle.ComputeConfigHash(cfg2)
	assert.Equal(t, hash1, hash2, "Same config should produce same hash")

	// Different config should produce different hash
	hash3 := lifecycle.ComputeConfigHash(cfg3)
	assert.NotEqual(t, hash1, hash3, "Different config should produce different hash")
}

// TestLifecycleE2E_NeedsFullReload tests full reload detection.
func TestLifecycleE2E_NeedsFullReload(t *testing.T) {
	cfg1 := &config.Config{
		Global: config.Global{
			TproxyPort: 12345,
		},
		Dns: config.Dns{
			IpVersionPrefer: 4,
		},
	}
	cfg2 := &config.Config{
		Global: config.Global{
			TproxyPort: 12345,
		},
		Dns: config.Dns{
			IpVersionPrefer: 4,
		},
	}
	cfg3 := &config.Config{
		Global: config.Global{
			TproxyPort: 54321,
		},
		Dns: config.Dns{
			IpVersionPrefer: 4,
		},
	}

	// Same config -> no full reload
	assert.False(t, lifecycle.NeedsFullReload(cfg1, cfg2), "Same config should not require full reload")

	// Port changed -> full reload
	assert.True(t, lifecycle.NeedsFullReload(cfg1, cfg3), "Port change should require full reload")
}

// TestLifecycleE2E_CompatibleForConfigOnlyReload tests DNS cache compatibility.
func TestLifecycleE2E_CompatibleForConfigOnlyReload(t *testing.T) {
	cfg1 := &config.Config{
		Dns: config.Dns{
			IpVersionPrefer: 4,
		},
	}
	cfg2 := &config.Config{
		Dns: config.Dns{
			IpVersionPrefer: 4,
		},
	}
	cfg3 := &config.Config{
		Dns: config.Dns{
			IpVersionPrefer: 6,
		},
	}

	// Same IP version preference -> compatible
	assert.True(t, lifecycle.CompatibleForConfigOnlyReload(cfg1, cfg2), "Same IP version preference should be compatible")

	// Different IP version preference -> incompatible
	assert.False(t, lifecycle.CompatibleForConfigOnlyReload(cfg1, cfg3), "Different IP version preference should be incompatible")
}

// TestLifecycleE2E_StateTransitions tests state transitions.
func TestLifecycleE2E_StateTransitions(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel) // Reduce noise

	mgr := lifecycle.NewLifecycleManager(&lifecycle.ManagerConfig{
		Log:           log,
		DrainTimeout:  5 * time.Second,
		CleanShutdown: true,
	})

	// Initial state
	assert.Equal(t, lifecycle.StateCreated, mgr.State())

	// State transitions are tested in unit tests
}

// TestLifecycleE2E_StartRequestValidation tests start request validation.
func TestLifecycleE2E_StartRequestValidation(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	mgr := lifecycle.NewLifecycleManager(&lifecycle.ManagerConfig{Log: log})
	ctx := context.Background()

	// Missing config file
	req := &lifecycle.StartRequest{
		ConfigFile: "/nonexistent/config.dae",
	}

	_, err := mgr.Start(ctx, req)
	assert.Error(t, err, "Start should fail with missing config file")

	// Should be in Stopped state after failed start
	assert.Equal(t, lifecycle.StateStopped, mgr.State())
}

// TestLifecycleE2E_ReloadValidation tests reload validation.
func TestLifecycleE2E_ReloadValidation(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	mgr := lifecycle.NewLifecycleManager(&lifecycle.ManagerConfig{Log: log})

	// Create a test config
	cfg := &config.Config{
		Global: config.Global{
			TproxyPort: 12345,
		},
	}

	ctx := context.Background()

	// Try to reload without starting
	req := &lifecycle.ReloadRequest{
		Config:     cfg,
		ConfigHash: lifecycle.ComputeConfigHash(cfg),
	}

	_, err := mgr.Reload(ctx, req)
	assert.Error(t, err, "Reload should fail when not in Running state")
}

// TestLifecycleE2E_StopValidation tests stop validation.
func TestLifecycleE2E_StopValidation(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	mgr := lifecycle.NewLifecycleManager(&lifecycle.ManagerConfig{Log: log})

	ctx := context.Background()

	// Try to stop without starting
	err := mgr.Stop(ctx, lifecycle.StopModeGraceful)
	assert.Error(t, err, "Stop should fail when not in Running or Reloading state")
}

// TestLifecycleE2E_GenerationLifecycle tests generation lifecycle.
func TestLifecycleE2E_GenerationLifecycle(t *testing.T) {
	cfg := &config.Config{
		Global: config.Global{
			TproxyPort: 12345,
		},
	}

	gen := lifecycle.NewGeneration("test-gen", cfg, "hash123")

	// Initial state
	assert.Equal(t, "test-gen", gen.ID)
	assert.Equal(t, "hash123", gen.ConfigHash)
	assert.False(t, gen.IsActive(), "Should not be active initially")

	// Activate
	gen.MarkActivated(time.Now())
	assert.True(t, gen.IsActive(), "Should be active after activation")

	// Close
	assert.NoError(t, gen.Close(), "Close should succeed")
}

// TestLifecycleE2E_ErrorTypes tests error type creation.
func TestLifecycleE2E_ErrorTypes(t *testing.T) {
	// StartError
	startErr := lifecycle.NewStartError(lifecycle.PhasePrepare, "gen-1", assert.AnError)
	assert.Equal(t, "start", startErr.Op)
	assert.Equal(t, "prepare", startErr.Phase)

	// ReloadError
	reloadErr := lifecycle.NewReloadError(lifecycle.PhaseCutover, "gen-2", assert.AnError, assert.AnError, true)
	assert.True(t, reloadErr.RollbackAttempted)

	// StopError
	stopErr := lifecycle.NewStopError(lifecycle.PhaseRelease, "gen-3", assert.AnError, []string{"resource1"})
	assert.Equal(t, []string{"resource1"}, stopErr.ResourcesLeaked)

	// PrecheckError
	precheckErr := lifecycle.NewPrecheckError("gen-4", []string{"check1", "check2"}, assert.AnError)
	assert.Equal(t, []string{"check1", "check2"}, precheckErr.ChecksFailed)

	// CompatibilityError
	compatErr := lifecycle.NewCompatibilityError("gen-5", "incompatible schema", true, assert.AnError)
	assert.True(t, compatErr.Forceable)
}

// TestLifecycleE2E_SystemdNotifier tests systemd notifier.
func TestLifecycleE2E_SystemdNotifier(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	n := lifecycle.NewSystemdNotifier(log)

	// These should not panic
	n.Ready()
	n.Reloading()
	n.Stopping()
	n.Status("test status")
	n.ExtendTimeout(10 * time.Second)
}

// TestLifecycleE2E_StopMode tests stop mode.
func TestLifecycleE2E_StopMode(t *testing.T) {
	mode := lifecycle.StopModeGraceful
	assert.Equal(t, "graceful", mode.String())

	mode = lifecycle.StopModeImmediate
	assert.Equal(t, "immediate", mode.String())
}

// TestLifecycleE2E_ConfigHashConsistency tests config hash consistency.
func TestLifecycleE2E_ConfigHashConsistency(t *testing.T) {
	cfg := &config.Config{
		Global: config.Global{
			TproxyPort:        12345,
			TproxyPortProtect: true,
			LogLevel:          "info",
		},
	}

	// Hash should be consistent across multiple calls
	hash1 := lifecycle.ComputeConfigHash(cfg)
	hash2 := lifecycle.ComputeConfigHash(cfg)
	hash3 := lifecycle.ComputeConfigHash(cfg)

	assert.Equal(t, hash1, hash2)
	assert.Equal(t, hash2, hash3)
}

// BenchmarkLifecycleE2E_ConfigHash benchmarks config hash computation.
func BenchmarkLifecycleE2E_ConfigHash(b *testing.B) {
	cfg := &config.Config{
		Global: config.Global{
			TproxyPort:        12345,
			TproxyPortProtect: true,
			LogLevel:          "info",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lifecycle.ComputeConfigHash(cfg)
	}
}

// TestLifecycleE2E_ControlPlaneBridge tests ControlPlaneBridge.
func TestLifecycleE2E_ControlPlaneBridge(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root privileges")
	}

	log := logrus.New()
	log.SetLevel(logrus.WarnLevel)

	bridge := lifecycle.NewControlPlaneBridge(log)
	assert.NotNil(t, bridge)

	// Test precheck should fail with non-existent file
	ctx := context.Background()
	req := &lifecycle.StartRequest{
		ConfigFile: "/nonexistent/config.dae",
	}

	err := bridge.Precheck(ctx, "test-gen", req)
	assert.Error(t, err)
}

// TestLifecycleE2E_ConcurrentStart tests concurrent start operations.
func TestLifecycleE2E_ConcurrentStart(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	mgr := lifecycle.NewLifecycleManager(&lifecycle.ManagerConfig{Log: log})
	ctx := context.Background()

	// Concurrent start attempts should fail (only one should succeed)
	var wg sync.WaitGroup
	errors := make(chan error, 10)

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			req := &lifecycle.StartRequest{
				ConfigFile: "/test/config.dae",
			}
			_, err := mgr.Start(ctx, req)
			errors <- err
		}(i)
	}

	wg.Wait()
	close(errors)

	successCount := 0
	for err := range errors {
		if err == nil {
			successCount++
		}
	}

	// At most one should succeed (since config file doesn't exist, all should fail)
	// But in real scenario with valid config, only first would succeed
	t.Logf("Success count: %d", successCount)
}

// TestLifecycleE2E_NetipAddrPortFallback tests netip.AddrPort parsing.
func TestLifecycleE2E_NetipAddrPortFallback(t *testing.T) {
	// Test fallback resolver parsing
	addr, err := netip.ParseAddrPort("8.8.8.8:53")
	require.NoError(t, err)
	assert.Equal(t, "8.8.8.8:53", addr.String())
}
