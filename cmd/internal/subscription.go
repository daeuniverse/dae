package internal

import (
	"encoding/json"
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/v2rayA/dae/common"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
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

func resolveSubscriptionAsBase64(log *logrus.Logger, b []byte) (nodes []string) {
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

func resolveSubscriptionAsSIP008(log *logrus.Logger, b []byte) (nodes []string, err error) {
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

func ResolveSubscription(log *logrus.Logger, subscription string) (nodes []string, err error) {
	log.Debugf("ResolveSubscription: %v", subscription)
	resp, err := http.Get(subscription)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if nodes, err = resolveSubscriptionAsSIP008(log, b); err == nil {
		return nodes, nil
	} else {
		log.Debugln(err)
	}
	return resolveSubscriptionAsBase64(log, b), nil
}
