/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, mzz2017 (mzz@tuta.io). All rights reserved.
 */

package assets

import (
	"errors"
	"github.com/adrg/xdg"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
)

func GetLocationAsset(filename string) (path string, err error) {
	// FIXME:
	folder := "dae"
	location := os.Getenv("DAE_LOCATION_ASSET")
	// check if DAE_LOCATION_ASSET is set
	if location != "" {
		// add DAE_LOCATION_ASSET to search path
		searchPaths := []string{
			filepath.Join(location, filename),
		}
		// additional paths for non windows platforms
		if runtime.GOOS != "windows" {
			searchPaths = append(
				searchPaths,
				filepath.Join("/usr/local/share", folder, filename),
				filepath.Join("/usr/share", folder, filename),
			)
		}
		for _, searchPath := range searchPaths {
			if _, err = os.Stat(searchPath); err != nil && errors.Is(err, fs.ErrNotExist) {
				continue
			}
			// return the first path that exists
			return searchPath, nil
		}
		// or download asset into DAE_LOCATION_ASSET
		return searchPaths[0], nil
	} else {
		if runtime.GOOS != "windows" {
			// search XDG data directories on non windows platform
			// symlink all assets into XDG_RUNTIME_DIR
			relpath := filepath.Join(folder, filename)
			fullpath, err := xdg.SearchDataFile(relpath)
			if err != nil {
				fullpath, err = xdg.DataFile(relpath)
				if err != nil {
					return "", err
				}
			}
			runtimepath, err := xdg.RuntimeFile(filepath.Join(folder, filename))
			if err != nil {
				return "", err
			}
			os.Remove(runtimepath)
			err = os.Symlink(fullpath, runtimepath)
			if err != nil {
				return "", err
			}
			return fullpath, err
		} else {
			// fallback to the old behavior of using only config dir on Windows
			// FIXME: conf.GetEnvironmentConfig().Config
			return filepath.Join("./", filename), nil
		}
	}
}
