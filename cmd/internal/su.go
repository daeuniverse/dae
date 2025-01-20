/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

package internal

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"os"
	"os/exec"
)

func AutoSu() {
	if os.Geteuid() == 0 {
		return
	}
	path, arg := trySudo()
	if path == "" {
		path, arg = tryDoas()
	}
	if path == "" {
		path, arg = tryPolkit()
	}

	if path == "" {
		return
	}
	logrus.Infof("use [ %s ] to elevate privileges to run [ %s ]", path, os.Args[0])
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
	if err != nil || !isExistAndExecutable(pathSudo) {
		return "", nil
	}
	// https://github.com/WireGuard/wireguard-tools/blob/71799a8f6d1450b63071a21cad6ed434b348d3d5/src/wg-quick/linux.bash#L85
	return pathSudo, []string{
		pathSudo,
		"-E",
		"-p",
		fmt.Sprintf("Please enter the password for %%u to continue: "),
		"--",
	}
}

func tryDoas() (path string, arg []string) {
	// https://man.archlinux.org/man/doas.1
	var err error
	path, err = exec.LookPath("doas")
	if err != nil {
		return "", nil
	}
	return path, []string{path, "-u", "root"}
}

func tryPolkit() (path string, arg []string) {
	// https://github.com/systemd/systemd/releases/tag/v256
	// introduced run0 which is a polkit wrapper.
	var possible = []string{"run0", "pkexec"}
	for _, v := range possible {
		path, err := exec.LookPath(v)
		if err != nil {
			continue
		}
		if isExistAndExecutable(path) {
			switch v {
			case "run0":
				return path, []string{path}
			case "pkexec":
				return path, []string{path, "--keep-cwd", "--user", "root"}
			}
		}
	}
	return "", nil
}

func isExistAndExecutable(path string) bool {
	if path == "" {
		return false
	}

	st, err := os.Stat(path)
	if err == nil {
		// https://stackoverflow.com/questions/60128401/how-to-check-if-a-file-is-executable-in-go
		return st.Mode()&0o111 == 0o111
	}
	return false
}
