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
	program := filepath.Base(os.Args[0])
	pathSudo, err := exec.LookPath("sudo")
	if err != nil {
		// skip
		return
	}
	// https://github.com/WireGuard/wireguard-tools/blob/71799a8f6d1450b63071a21cad6ed434b348d3d5/src/wg-quick/linux.bash#L85
	p, err := os.StartProcess(pathSudo, append([]string{
		pathSudo,
		"-E",
		"-p",
		fmt.Sprintf("%v must be run as root. Please enter the password for %%u to continue: ", program),
		"--",
	}, os.Args...), &os.ProcAttr{
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
