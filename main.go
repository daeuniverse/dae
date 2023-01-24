//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2022, mzz2017 (mzz@tuta.io). All rights reserved.
 */

package main

import (
	"github.com/sirupsen/logrus"
	"github.com/v2rayA/dae/component/control"
	"github.com/v2rayA/dae/pkg/logger"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	const (
		tproxyPort = 12345
		ifname     = "docker0"
	)
	logrus.SetLevel(logrus.DebugLevel)
	log := logger.NewLogger(2)
	log.Println("Running")
	t, err := control.NewControlPlane(log, `
default:proxy
ip(119.29.29.29) -> proxy
ip(223.5.5.5) -> direct
ip(geoip:cn) -> direct
domain(geosite:cn, domain:"ip.sb") -> direct
ip("91.105.192.0/23","91.108.4.0/22","91.108.8.0/21","91.108.16.0/21","91.108.56.0/22","95.161.64.0/20","149.154.160.0/20","185.76.151.0/24")->proxy
domain(geosite:category-scholar-!cn, geosite:category-scholar-cn)->direct
`)
	if err != nil {
		panic(err)
	}
	if err = t.BindLink(ifname); err != nil {
		panic(err)
	}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGKILL, syscall.SIGILL)
	go func() {
		if err := t.ListenAndServe(tproxyPort); err != nil {
			log.Errorln("ListenAndServe:", err)
			sigs <- nil
		}
	}()
	<-sigs
	if e := t.Close(); e != nil {
		log.Errorln("Close control plane:", err)
	}
}
