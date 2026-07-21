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

func validateSubscriptionNodes(log *logrus.Logger, tag string, nodes []string) []string {
	valid := make([]string, 0, len(nodes))
	for i, node := range nodes {
		_, matched, err := common.ParseProxyChain(node)
		if err == nil && matched {
			_, groupChain, groupErr := common.ParseGroupChain(node)
			if groupChain {
				if groupErr != nil {
					err = groupErr
				} else {
					err = fmt.Errorf("group entry chains are not allowed in subscriptions")
				}
			}
		}
		if err != nil {
			log.WithFields(logrus.Fields{
				"subscription": tag,
				"node_index":   i,
				"reason":       err.Error(),
			}).Error("skip invalid subscription node")
			continue
		}
		valid = append(valid, node)
	}
	return valid
}

func resolveSubscriptionContent(log *logrus.Logger, tag string, b []byte) []string {
	nodes, err := ResolveSubscriptionAsSIP008(log, b)
	if err != nil {
		log.Debugln(err)
		nodes = ResolveSubscriptionAsBase64(log, b)
	}
	return validateSubscriptionNodes(log, tag, nodes)
}

func readPersistedSubscription(configDir, tag string) ([]byte, error) {
	return ResolveFile(&url.URL{Host: "persist.d/" + tag + ".sub"}, configDir)
}

func writePersistedSubscription(configDir, tag string, b []byte) (err error) {
	dir := filepath.Join(configDir, "persist.d")
	path := filepath.Join(dir, tag+".sub")
	if err := common.EnsureFileInSubDir(path, dir); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".dae-sub-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()
	if err = tmp.Chmod(0600); err != nil {
		return err
	}
	if _, err = tmp.Write(b); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func ResolveSubscription(log *logrus.Logger, client *http.Client, configDir string, subscription string) (tag string, nodes []string, err error) {
	/// Get tag.
	tag, subscription = common.GetTagFromLinkLikePlaintext(subscription)

	/// Parse url.
	u, err := url.Parse(subscription)
	if err != nil {
		return tag, nil, fmt.Errorf("failed to parse subscription \"%v\": %w", subscription, err)
	}
	log.WithField("subscription", tag).Debug("ResolveSubscription")
	var (
		b    []byte
		req  *http.Request
		resp *http.Response
	)

	persistToFile := false
	fetchedRemote := false

	switch u.Scheme {
	case "file":
		b, err = ResolveFile(u, configDir)
		if err != nil {
			return tag, nil, err
		}
		goto validate
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
		return tag, nil, err
	}
	req.Header.Set("User-Agent", fmt.Sprintf("dae/%v (like v2rayA/1.0 WebRequestHelper) (like v2rayN/1.0 WebRequestHelper)", config.Version))
	resp, err = client.Do(req)
	if err != nil {
		if persistToFile {
			log.Warnln("failed to fetch subscription, try to read from file")
			b, err = readPersistedSubscription(configDir, tag)

			if err != nil {
				return tag, nil, err
			}
			goto validate
		}

		return tag, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err = io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB max subscription size
	if err != nil {
		return tag, nil, err
	}
	fetchedRemote = true

validate:
	nodes = resolveSubscriptionContent(log, tag, b)
	if len(nodes) == 0 {
		if persistToFile && fetchedRemote {
			log.WithField("subscription", tag).Error("subscription contains no valid nodes; use last valid cache")
			cached, cacheErr := readPersistedSubscription(configDir, tag)
			if cacheErr == nil {
				if cachedNodes := resolveSubscriptionContent(log, tag, cached); len(cachedNodes) > 0 {
					return tag, cachedNodes, nil
				}
			}
		}
		return tag, nil, fmt.Errorf("subscription %q contains no valid nodes", tag)
	}
	if persistToFile && fetchedRemote {
		if err := writePersistedSubscription(configDir, tag, b); err != nil {
			return tag, nil, err
		}
	}
	return tag, nodes, nil
}
