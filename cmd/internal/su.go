/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

package internal

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/sirupsen/logrus"
)

func AutoSu() {
	if os.Getuid() == 0 {
		return
	}
	path, arg := tryDesktopSudo()
	if path == "" {
		path, arg = trySudo()
	}
	if path == "" {
		return
	}
	p, err := os.StartProcess(path, append(arg, os.Args...), &os.ProcAttr{
		Files: []*os.File{
			os.Stdin,
			os.Stdout,
			os.Stderr,
		},
	})
	if err != nil {
		logrus.Fatal(err)
	}
	stat, err := p.Wait()
	if err != nil {
		os.Exit(1)
	}
	os.Exit(stat.ExitCode())
}

func trySudo() (path string, arg []string) {
	pathSudo, err := exec.LookPath("sudo")
	if err != nil {
		// fallback
		var possibleSudoPath = []string{
			"/usr/bin/sudo", "/usr/sbin/sudo",
		}
		var found = false
		for _, v := range possibleSudoPath {
			if isExistAndExecutable(v) {
				pathSudo = v
				found = true
				break
			}
		}
		if !found {
			return "", nil
		}
	}
	// https://github.com/WireGuard/wireguard-tools/blob/71799a8f6d1450b63071a21cad6ed434b348d3d5/src/wg-quick/linux.bash#L85
	return pathSudo, []string{
		pathSudo,
		"-E",
		"-p",
		fmt.Sprintf("%v must be run as root. Please enter the password for %%u to continue: ", filepath.Base(os.Args[0])),
		"--",
	}
}

func tryDesktopSudo() (path string, arg []string) {
	// https://specifications.freedesktop.org/desktop-entry-spec/latest
	desktop := os.Getenv("XDG_CURRENT_DESKTOP")
	if desktop != "" {
		var possible = []string{"pkexec"}
		for _, v := range possible {
			path, err := exec.LookPath(v)
			if err != nil {
				continue
			}
			if isExistAndExecutable(path) {
				switch v {
				case "pkexec":
					return path, []string{path, "--keep-cwd", "--user", "root"}
				}
			}
		}
	}
	return "", nil
}

func isExistAndExecutable(path string) bool {
	st, err := os.Stat(path)
	if err == nil {
		// https://stackoverflow.com/questions/60128401/how-to-check-if-a-file-is-executable-in-go
		if st.Mode()&0o111 == 0o111 {
			return true
		}
	}
	return false
}
