/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

package assets

import (
	"errors"
	"fmt"
	"github.com/daeuniverse/dae/common/consts"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/adrg/xdg"
	"github.com/sirupsen/logrus"
)

const CacheTimeout = 5 * time.Second

type CacheItem struct {
	Filename string
	Path     string

	CacheDeadline time.Time
}

type LocationFinder struct {
	mu         sync.Mutex
	m          map[string]CacheItem
	externDirs []string
}

func NewLocationFinder(externDirPath []string) *LocationFinder {
	return &LocationFinder{
		mu:         sync.Mutex{},
		m:          map[string]CacheItem{},
		externDirs: externDirPath,
	}
}

func (c *LocationFinder) GetLocationAsset(log *logrus.Logger, filename string) (path string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Search cache.
	if item, ok := c.m[filename]; ok && time.Now().Before(item.CacheDeadline) {
		return item.Path, nil
	}
	defer func() {
		if err == nil {
			c.m[filename] = CacheItem{
				Filename:      filename,
				Path:          path,
				CacheDeadline: time.Now().Add(CacheTimeout),
			}
			time.AfterFunc(CacheTimeout, func() {
				c.mu.Lock()
				defer c.mu.Unlock()
				if item, ok := c.m[filename]; ok && time.Now().After(item.CacheDeadline) {
					delete(c.m, filename)
				}
			})
		}
	}()

	// Search dirs.
	var searchDirs []string
	folder := consts.AppName
	// check if DAE_LOCATION_ASSET is set
	location := os.Getenv("DAE_LOCATION_ASSET")
	if location != "" {
		// add DAE_LOCATION_ASSET to search path
		searchDirs = append(searchDirs, location)
		// add /etc/dae to search path
		searchDirs = append(searchDirs, c.externDirs...)
		// additional paths for non windows platforms
		if runtime.GOOS != "windows" {
			searchDirs = append(
				searchDirs,
				filepath.Join("/usr/local/share", folder),
				filepath.Join("/usr/share", folder),
			)
		}
		searchDirs = append(searchDirs, c.externDirs...)
	} else {
		// add /etc/dae to search path
		searchDirs = append(searchDirs, c.externDirs...)
		if runtime.GOOS != "windows" {
			// Search XDG data directories on non windows platform
			xdgDirs := append([]string{xdg.DataHome}, xdg.DataDirs...)
			for i := range xdgDirs {
				xdgDirs[i] = filepath.Join(xdgDirs[i], folder)
			}
			searchDirs = append(searchDirs, xdgDirs...)
		} else {
			// fallback to the old behavior of using only current dir on Windows
			pwd := "./"
			if absPath, e := filepath.Abs(pwd); e == nil {
				pwd = absPath
			}
			searchDirs = append(searchDirs, pwd)
		}
	}
	log.Debugf(`Search "%v" in [%v]`, filename, strings.Join(searchDirs, ", "))
	for _, searchDir := range searchDirs {
		searchPath := filepath.Join(searchDir, filename)
		if _, err = os.Stat(searchPath); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return "", err
		}
		log.Debugf(`Found "%v" at %v`, filename, searchPath)
		// return the first path that exists
		return searchPath, nil
	}
	return "", fmt.Errorf("%v: %w in [%v]", filename, os.ErrNotExist, strings.Join(searchDirs, ", "))
}
