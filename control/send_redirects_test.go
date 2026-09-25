/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/stretchr/testify/require"
)

// redirectConfFixture points procSysNet at a throwaway copy of the sysctl nodes
// that decide whether the kernel sends a redirect out of an interface.
//
// /proc/sys/net is root-owned, so a test touching the real tree would have to be
// skipped in CI and the write/check pair would ship without an executable
// contract. nodes maps a node name ("<ifname>" or "all") to the value to write;
// a node left out of the map is left absent.
func redirectConfFixture(t *testing.T, nodes map[string]string) string {
	t.Helper()

	root := t.TempDir()
	previous := procSysNet
	procSysNet = root
	t.Cleanup(func() { procSysNet = previous })

	for node, value := range nodes {
		dir := filepath.Join(root, "ipv4", "conf", node)
		require.NoError(t, os.MkdirAll(dir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "send_redirects"), []byte(value), 0o644))
	}
	return filepath.Join(root, "ipv4", "conf")
}

func readRedirectConf(t *testing.T, confDir, node string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(confDir, node, "send_redirects"))
	require.NoError(t, err)
	return string(b)
}

// TestCheckSendRedirectsRejectsConfAll is the regression this file exists for.
//
// The kernel ORs the two nodes (IN_DEV_TX_REDIRECTS is IN_DEV_ORCONF, and
// ip-sysctl.rst says redirects are on if at least one of
// conf/{all,interface}/send_redirects is TRUE), so a "0" written only to the
// per-interface node is inert while conf/all keeps the kernel default of 1. The
// old check read the per-interface node alone - the very value dae had just
// written - so it could not fail while redirects were still being sent, and dae
// kept advertising a route that leads clients around itself.
func TestCheckSendRedirectsRejectsConfAll(t *testing.T) {
	redirectConfFixture(t, map[string]string{"dae0": "0", "all": "1"})

	err := CheckSendRedirects("dae0")
	require.Error(t, err, "conf/all/send_redirects=1 still enables redirects out of dae0")
	require.Contains(t, err.Error(), filepath.Join("conf", "all", "send_redirects"),
		"the error must name the node that is actually keeping redirects on")
}

// TestSetSendRedirectsTurnsOffConfAll pins that one SetSendRedirects call writes
// every node the decision depends on. Writing the kernel default back is the
// part that makes the per-interface write take effect.
func TestSetSendRedirectsTurnsOffConfAll(t *testing.T) {
	confDir := redirectConfFixture(t, map[string]string{"dae0": "1", "all": "1"})

	SetSendRedirects("dae0", "0")

	require.Equal(t, "0", readRedirectConf(t, confDir, "dae0"))
	require.Equal(t, "0", readRedirectConf(t, confDir, "all"),
		"conf/all/send_redirects has to be overwritten, otherwise the per-interface write changes nothing")
	require.NoError(t, CheckSendRedirects("dae0"),
		"the write and the check have to agree once both nodes are off")
}

// TestSetSendRedirectsAttemptsConfAllAfterFailure keeps the two writes
// independent: conf/all is the node that decides, so a failure on the
// per-interface node must not skip it. A directory standing in for the node
// fails the write for every uid, so this does not depend on running unprivileged.
func TestSetSendRedirectsAttemptsConfAllAfterFailure(t *testing.T) {
	confDir := redirectConfFixture(t, map[string]string{"dae0": "1", "all": "1"})

	perIface := filepath.Join(confDir, "dae0", "send_redirects")
	require.NoError(t, os.Remove(perIface))
	require.NoError(t, os.Mkdir(perIface, 0o755))

	require.Error(t, setSendRedirects("dae0", consts.IpVersionStr_4, "0"),
		"a failed write has to be reported instead of being silently dropped")
	require.Equal(t, "0", readRedirectConf(t, confDir, "all"),
		"conf/all is the node that decides, so it must still be written")
}

// TestCheckSendRedirectsFailsClosed pins that an unreadable node is reported as
// an error rather than read as "off".
func TestCheckSendRedirectsFailsClosed(t *testing.T) {
	redirectConfFixture(t, map[string]string{"dae0": "0"}) // conf/all missing

	require.Error(t, CheckSendRedirects("dae0"))
}
