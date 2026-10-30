/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

import (
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
)

// UIBasePath is where a configured frontend is served. The frontend itself is
// static and therefore public, while every API call it makes still needs the
// token.
const UIBasePath = "/ui/"

// hasUI reports whether a frontend directory was configured. The frontend uses
// hash routing, so only extensionless misses fall back to index.html.
// uiRootDir normalizes the configured frontend directory. A directory that is
// missing or has no index.html is not fatal: the listener starts, answers 404
// under /ui/ and logs a warning, so a broken UI never keeps the proxy down.
func uiRootDir(dir string) (string, string) {
	root, err := filepath.Abs(dir)
	if err != nil {
		return filepath.Clean(dir), fmt.Sprintf("cannot resolve %q: %v", dir, err)
	}
	root = filepath.Clean(root)
	if info, err := os.Stat(root); err != nil {
		return root, fmt.Sprintf("%q is not usable, /ui/ answers 404: %v", root, err)
	} else if !info.IsDir() {
		return root, fmt.Sprintf("%q is not a directory, /ui/ answers 404", root)
	}
	index := filepath.Join(root, "index.html")
	if info, err := os.Stat(index); err != nil {
		return root, fmt.Sprintf("%q has no index.html, /ui/ answers 404: %v", root, err)
	} else if info.IsDir() {
		return root, fmt.Sprintf("%q is a directory, /ui/ answers 404", index)
	}
	return root, ""
}

func (s *Server) hasUI() bool {
	return s.uiRoot != ""
}

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	if !isReadMethod(r.Method) {
		writeMethodNotAllowed(w, requestIDFromContext(r.Context()), "GET, HEAD")
		return
	}

	if raw := r.URL.Path; raw == "/" || raw == "/ui" {
		http.Redirect(w, r, UIBasePath, http.StatusFound)
		return
	}
	cleaned := path.Clean(r.URL.Path)
	if cleaned == "/ui" {
		s.serveUIFile(w, r, "/index.html", false)
		return
	}
	// A path such as /ui/../api/v1/runtime escapes the namespace after
	// normalization; it is not a UI file and must not reach the API either.
	if !strings.HasPrefix(cleaned, UIBasePath) {
		s.writeUINotFound(w, r)
		return
	}

	rel := "/" + strings.TrimPrefix(cleaned, UIBasePath)
	info, err := os.Stat(s.uiRoot + rel)
	if err == nil && info.IsDir() {
		// No directory listing: only the injected index.html is a valid page.
		s.writeUINotFound(w, r)
		return
	}
	if err != nil {
		if path.Ext(rel) != "" {
			// A missing asset, font, manifest or service worker is a real 404,
			// never an HTML fallback the browser would misparse.
			s.writeUINotFound(w, r)
			return
		}
		s.serveUIFile(w, r, "/index.html", true)
		return
	}
	s.serveUIFile(w, r, rel, false)
}

func (s *Server) serveUIFile(w http.ResponseWriter, r *http.Request, name string, fallback bool) {
	file, err := os.Open(s.uiRoot + name)
	if err != nil {
		s.writeUINotFound(w, r)
		return
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || info.IsDir() {
		s.writeUINotFound(w, r)
		return
	}

	// Content-hashed bundles can be cached hard; pages and lookups must not be.
	if strings.HasPrefix(name, "/assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	if fallback {
		w.Header().Set("X-Native-UI-Fallback", "index")
	}
	if path.Ext(name) == ".webmanifest" {
		// go's mime table does not know the web app manifest type.
		w.Header().Set("Content-Type", "application/manifest+json")
	}
	http.ServeContent(w, r, name, info.ModTime(), file)
}

func (s *Server) writeUINotFound(w http.ResponseWriter, r *http.Request) {
	writeError(w, requestIDFromContext(r.Context()), http.StatusNotFound, codeResourceNotFound, "UI file not found")
}

// logUITarget keeps unexpected UI requests diagnosable without letting a caller
// grow the log with an unbounded path.
func logUITarget(r *http.Request) string {
	const limit = 200
	target := r.URL.EscapedPath()
	if len(target) > limit {
		target = target[:limit] + "..."
	}
	return target
}

func uiLogFields(r *http.Request, status int) logrus.Fields {
	if status < http.StatusBadRequest || !strings.HasPrefix(r.URL.Path, UIBasePath) {
		return nil
	}
	return logrus.Fields{"target": logUITarget(r)}
}
