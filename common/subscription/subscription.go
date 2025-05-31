/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package subscription

import (
	"bufio"
	"bytes"
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
	lines := strings.Split(raw, "\n")
	for _, line := range lines {
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
		u := url.URL{
			Scheme:   "ss",
			User:     url.UserPassword(server.Method, server.Password),
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
	defer f.Close()
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

func ResolveSubscription(log *logrus.Logger, client *http.Client, configDir string, subscription string) (tag string, nodes []string, err error) {
	/// Get tag.
	tag, subscription = common.GetTagFromLinkLikePlaintext(subscription)

	/// Parse url.
	u, err := url.Parse(subscription)
	if err != nil {
		return tag, nil, fmt.Errorf("failed to parse subscription \"%v\": %w", subscription, err)
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
		break
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
			u.Host = "persist.d/" + tag + ".sub"
			u.Path = ""
			b, err = ResolveFile(u, configDir)

			if err != nil {
				return "", nil, err
			}
			goto resolve
		}

		return "", nil, err
	}
	defer resp.Body.Close()
	b, err = io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, err
	}

	if persistToFile {
		path := filepath.Join(configDir, "persist.d")
		if _, err := os.Stat(path); os.IsNotExist(err) {
			err := os.MkdirAll(path, 0700)
			if err != nil {
				return "", nil, err
			}
		}

		path = filepath.Join(path, tag+".sub")
		file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return "", nil, err
		}
		defer file.Close()

		_, err = file.Write(b)
		if err != nil {
			return "", nil, err
		}
	}
resolve:
	if nodes, err = ResolveSubscriptionAsSIP008(log, b); err == nil {
		return tag, nodes, nil
	} else {
		log.Debugln(err)
	}
	return tag, ResolveSubscriptionAsBase64(log, b), nil
}
