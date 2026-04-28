/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"github.com/daeuniverse/dae/config"
	"github.com/sirupsen/logrus"
)

type Runner struct {
	log               *logrus.Logger
	conf              *config.Config
	externGeoDataDirs []string
}

func newRunner(log *logrus.Logger, conf *config.Config, externGeoDataDirs []string) *Runner {
	return &Runner{
		log:               log,
		conf:              conf,
		externGeoDataDirs: externGeoDataDirs,
	}
}
