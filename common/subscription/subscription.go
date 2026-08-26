/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package subscription

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/config"
	"github.com/sirupsen/logrus"
)

type sip008 struct {
	Version        int            `json:"version"`
	Servers        []sip008Server `json:"servers"`
	BytesUsed      int64          `json:"bytes_used"`
	BytesRemaining int64          `json:"bytes_remaining"`
}

type sip008Server struct {
	Id         string `json:"id"`
	Remarks    string `json:"remarks"`
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
	Password   string `json:"password"`
	Method     string `json:"method"`
	Plugin     string `json:"plugin"`
	PluginOpts string `json:"plugin_opts"`
}

func ResolveSubscriptionAsBase64(log *logrus.Logger, b []byte) (nodes []string) {
	log.Debugln("Try to resolve as base64")

	// base64 decode
	raw, e := common.Base64StdDecode(string(b))
	if e != nil {
		raw, _ = common.Base64UrlDecode(string(b))
	}

	// Simply check and preprocess.
	lines := strings.SplitSeq(raw, "\n")
	for line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		protocol, suffix, _ := strings.Cut(line, "://")
		if len(protocol) == 0 || len(suffix) == 0 {
			continue
		}
		nodes = append(nodes, line)
	}
	return nodes
}

func ResolveSubscriptionAsSIP008(log *logrus.Logger, b []byte) (nodes []string, err error) {
	log.Debugln("Try to resolve as sip008")

	var sip sip008
	err = json.Unmarshal(b, &sip)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal json to sip008")
	}
	if sip.Version != 1 || sip.Servers == nil {
		return nil, fmt.Errorf("does not seems like a standard sip008 subscription")
	}
	for _, server := range sip.Servers {
		userinfo := base64.RawURLEncoding.EncodeToString([]byte(server.Method + ":" + server.Password))
		u := url.URL{
			Scheme:   "ss",
			User:     url.User(userinfo),
			Host:     net.JoinHostPort(server.Server, strconv.Itoa(server.ServerPort)),
			RawQuery: url.Values{"plugin": []string{server.PluginOpts}}.Encode(),
			Fragment: server.Remarks,
		}
		nodes = append(nodes, u.String())
	}
	return nodes, nil
}

func ResolveFile(u *url.URL, configDir string) (b []byte, err error) {
	if u.Host == "" {
		return nil, fmt.Errorf("not support absolute path")
	}
	/// Relative location.
	// Make sure path is secure.
	path := filepath.Join(configDir, u.Host, u.Path)
	if err = common.EnsureFileInSubDir(path, configDir); err != nil {
		return nil, err
	}
	/// Read and resolve.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	// Check file access.
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("subscription file cannot be a directory: %v", path)
	}
	if fi.Mode()&0037 > 0 {
		return nil, fmt.Errorf("permissions %04o for '%v' are too open; requires the file is NOT writable by the same group and NOT accessible by others; suggest 0640 or 0600", fi.Mode()&0777, path)
	}
	// Resolve the first line instruction.
	fReader := bufio.NewReader(f)
	b, err = fReader.Peek(1)
	if err != nil {
		return nil, err
	}
	if string(b[0]) == "@" {
		// Instruction line. But not support yet.
		_, _, err = fReader.ReadLine()
		if err != nil {
			return nil, err
		}
	}

	b, err = io.ReadAll(fReader)
	if err != nil {
		return nil, err
	}
	return bytes.TrimSpace(b), err
}

func resolveSubscriptionForPersist(log *logrus.Logger, b []byte) ([]string, error) {
	nodes, err := ResolveSubscriptionAsSIP008(log, b)
	if err == nil {
		if len(nodes) == 0 {
			return nil, fmt.Errorf("subscription contains no nodes")
		}
		return nodes, nil
	}
	log.Debugln(err)

	nodes = ResolveSubscriptionAsBase64(log, b)
	if len(nodes) == 0 {
		return nil, fmt.Errorf("subscription contains no valid nodes")
	}
	return nodes, nil
}

func resolvePersistedSubscription(u *url.URL, configDir, tag string) ([]byte, error) {
	persisted := *u
	persisted.Host = "persist.d/" + tag + ".sub"
	persisted.Path = ""
	return ResolveFile(&persisted, configDir)
}

func writeSubscriptionAtomically(path string, b []byte) (err error) {
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := file.Name()
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(tmpPath)
		}
	}()

	if err = file.Chmod(0600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err = file.Write(b); err != nil {
		_ = file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmpPath, path); err != nil {
		return err
	}
	renamed = true
	return nil
}

func ResolveSubscription(log *logrus.Logger, client *http.Client, configDir string, subscription string) (tag string, nodes []string, err error) {
	tag, subscription = common.GetTagFromLinkLikePlaintext(subscription)

	u, err := url.Parse(subscription)
	if err != nil {
		return tag, nil, fmt.Errorf("failed to parse subscription %q: %w", subscription, err)
	}
	log.Debugf("ResolveSubscription: %v", subscription)
	var (
		b    []byte
		req  *http.Request
		resp *http.Response
	)

	persistToFile := false

	switch u.Scheme {
	case "file":
		b, err = ResolveFile(u, configDir)
		if err != nil {
			return "", nil, err
		}
		goto resolve
	case "http-file", "https-file":
		if len(tag) == 0 {
			return "", nil, fmt.Errorf("tag is required for http-file/https-file subscription")
		}
		persistToFile = true
		subscription = strings.Replace(subscription, "-file", "", 1)
	default:
	}
	req, err = http.NewRequest("GET", subscription, nil)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("User-Agent", fmt.Sprintf("dae/%v (like v2rayA/1.0 WebRequestHelper) (like v2rayN/1.0 WebRequestHelper)", config.Version))
	resp, err = client.Do(req)
	if err != nil {
		if persistToFile {
			log.Warnln("failed to fetch subscription, try to read from file")
			b, err = resolvePersistedSubscription(u, configDir, tag)
			if err != nil {
				return "", nil, err
			}
			goto resolve
		}
		return "", nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		statusErr := fmt.Errorf("subscription request returned HTTP status %s", resp.Status)
		if persistToFile {
			log.Warnf("%v, try to read from file", statusErr)
			b, err = resolvePersistedSubscription(u, configDir, tag)
			if err != nil {
				return "", nil, fmt.Errorf("%v; failed to read persisted subscription: %w", statusErr, err)
			}
			goto resolve
		}
		return "", nil, statusErr
	}

	b, err = io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return "", nil, err
	}

	if persistToFile {
		resolvedNodes, resolveErr := resolveSubscriptionForPersist(log, b)
		if resolveErr != nil {
			log.Warnf("fetched subscription is invalid (%v), try to read from file", resolveErr)
			b, err = resolvePersistedSubscription(u, configDir, tag)
			if err != nil {
				return "", nil, fmt.Errorf("fetched subscription is invalid: %v; failed to read persisted subscription: %w", resolveErr, err)
			}
			goto resolve
		}

		persistDir := filepath.Join(configDir, "persist.d")
		if _, statErr := os.Stat(persistDir); os.IsNotExist(statErr) {
			if err := os.MkdirAll(persistDir, 0700); err != nil {
				return "", nil, err
			}
		} else if statErr != nil {
			return "", nil, statErr
		}

		persistPath := filepath.Join(persistDir, tag+".sub")
		if err = writeSubscriptionAtomically(persistPath, b); err != nil {
			return "", nil, err
		}
		return tag, resolvedNodes, nil
	}

resolve:
	if nodes, err = ResolveSubscriptionAsSIP008(log, b); err == nil {
		return tag, nodes, nil
	} else {
		log.Debugln(err)
	}
	return tag, ResolveSubscriptionAsBase64(log, b), nil
}
