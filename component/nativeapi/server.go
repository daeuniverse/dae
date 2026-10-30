/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	defaultMaxRequestTargetBytes = 8192
	defaultMaxHeaderBytes        = 8192
	defaultMaxJSONBodyBytes      = 65536
)

type Config struct {
	Listen                 string
	Secret                 string
	AllowAnonymousLoopback bool
	AllowOrigins           []string
	AllowedHosts           []string
	EngineName             string
	EngineVersion          string
	BuildRevision          string
	BuildTarget            string
	BuildBuiltAt           string
	MaxRequestTargetBytes  int
	MaxHeaderBytes         int
	MaxJSONBodyBytes       int
	UI                     string
}

type Server struct {
	cfg      Config
	provider RuntimeProvider
	log      *logrus.Logger

	groups     GroupProvider
	operations OperationProvider
	traffic    TrafficHistoryProvider
	nodes      NodeProvider

	httpServer *http.Server
	listener   net.Listener

	listenHost         string
	listenPort         int
	listenerIsLoopback bool
	wildcardListen     bool
	allowedOrigins     map[string]struct{}
	allowedHosts       []hostAuthority
	uiRoot             string

	served    atomic.Uint64
	refused   atomic.Uint64
	summaryMu sync.Mutex
	summaryOn bool
	stopOnce  sync.Once
	stop      chan struct{}
	done      chan struct{}
}

func NewServer(cfg Config, provider RuntimeProvider, log *logrus.Logger) (*Server, error) {
	if provider == nil {
		return nil, fmt.Errorf("native API runtime provider is nil")
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:9527"
	}
	host, portStr, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("api.listen: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("api.listen %q: host must be a numeric IP", cfg.Listen)
	}
	port, err := portFromString(portStr)
	if err != nil {
		return nil, fmt.Errorf("api.listen %q: %w", cfg.Listen, err)
	}
	if cfg.EngineName == "" {
		cfg.EngineName = EngineName
	}
	if cfg.EngineVersion == "" {
		cfg.EngineVersion = "unknown"
	}
	if cfg.MaxRequestTargetBytes <= 0 {
		cfg.MaxRequestTargetBytes = defaultMaxRequestTargetBytes
	}
	if cfg.MaxHeaderBytes <= 0 {
		cfg.MaxHeaderBytes = defaultMaxHeaderBytes
	}
	if cfg.MaxJSONBodyBytes <= 0 {
		cfg.MaxJSONBodyBytes = defaultMaxJSONBodyBytes
	}

	s := &Server{
		cfg:                cfg,
		provider:           provider,
		log:                log,
		listenHost:         host,
		listenPort:         port,
		listenerIsLoopback: ip.IsLoopback(),
		wildcardListen:     ip.IsUnspecified(),
		allowedOrigins:     make(map[string]struct{}, len(cfg.AllowOrigins)),
	}
	for _, origin := range cfg.AllowOrigins {
		s.allowedOrigins[origin] = struct{}{}
	}
	for _, value := range cfg.AllowedHosts {
		host, port, ok := parseAuthority(value, 80)
		if !ok {
			return nil, fmt.Errorf("api.allowed_hosts %q: invalid host authority", value)
		}
		s.allowedHosts = append(s.allowedHosts, hostAuthority{host: host, port: port})
	}
	if cfg.UI != "" {
		root, warning := uiRootDir(cfg.UI)
		s.uiRoot = root
		if warning != "" && s.log != nil {
			s.log.Warnln("Native API UI:", warning)
		}
	}
	return s, nil
}

func (s *Server) SetGroupProvider(provider GroupProvider) {
	if s == nil {
		return
	}
	s.groups = provider
}

func (s *Server) SetOperationProvider(provider OperationProvider) {
	if s == nil {
		return
	}
	s.operations = provider
}

func (s *Server) SetTrafficHistoryProvider(provider TrafficHistoryProvider) {
	if s == nil {
		return
	}
	s.traffic = provider
}

func (s *Server) SetNodeProvider(provider NodeProvider) {
	if s == nil {
		return
	}
	s.nodes = provider
}

func portFromString(value string) (int, error) {
	port, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid port: %w", err)
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("port must be in 1..65535")
	}
	return port, nil
}

func (s *Server) Start() error {
	listener, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	s.listener = listener
	s.httpServer = &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    s.cfg.MaxHeaderBytes,
	}
	go func() {
		err := s.httpServer.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) && s.log != nil {
			s.log.WithError(err).Errorln("native API listener stopped")
		}
	}()
	s.startAccessSummary()
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s == nil || s.httpServer == nil {
		return nil
	}
	err := s.httpServer.Shutdown(ctx)
	s.stopAccessSummary()
	if s.log != nil {
		if err != nil {
			s.log.WithError(err).Warnln("Native API listener did not shut down cleanly")
		} else {
			s.log.Infoln("Native API listener stopped")
		}
	}
	return err
}

func (s *Server) Addr() net.Addr {
	if s == nil || s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

type contextKey uint8

const (
	requestIDKey contextKey = iota
	fullDiscoveryKey
)

func requestIDFromContext(ctx context.Context) string {
	requestID, _ := ctx.Value(requestIDKey).(string)
	return requestID
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	recorder := &responseRecorder{ResponseWriter: w}
	defer func() { s.logRequest(recorder, r, started) }()
	w = recorder

	requestID := newRequestID()
	ctx := context.WithValue(r.Context(), requestIDKey, requestID)
	r = r.WithContext(ctx)

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if len(r.RequestURI) > s.cfg.MaxRequestTargetBytes {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "request target is too large")
		return
	}
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && r.ContentLength > 0 {
		writeError(w, requestID, http.StatusBadRequest, codeInvalidRequest, "GET and HEAD requests must not carry a body")
		return
	}
	if r.ContentLength > int64(s.cfg.MaxJSONBodyBytes) {
		writeError(w, requestID, http.StatusRequestEntityTooLarge, codeRequestTooLarge, "request body is too large")
		return
	}
	// net/http admits MaxHeaderBytes plus its own bufio slop and then answers
	// with a bare text 431, so the advertised limit is enforced here.
	if requestHeaderBytes(r) > s.cfg.MaxHeaderBytes {
		writeError(w, requestID, http.StatusRequestEntityTooLarge, codeRequestTooLarge, "request headers are too large")
		return
	}
	if !s.hostAllowed(r.Host) {
		writeError(w, requestID, http.StatusForbidden, codePermissionDenied, "host is not allowed")
		return
	}
	if r.Method == http.MethodOptions {
		s.handlePreflight(w, r)
		return
	}
	if !s.originAllowed(r) {
		writeError(w, requestID, http.StatusForbidden, codePermissionDenied, "origin is not allowed")
		return
	}
	s.setCORSHeaders(w, r)

	// Route before authenticating: only /api belongs to the control plane. The
	// static frontend cannot carry a bearer on <script src>, and a request for
	// any other path is a navigation, not an API call.
	switch {
	case isAPIPath(r.URL.Path):
		// Handled below, after authentication.
	case s.hasUI() && (r.URL.Path == "/ui" || strings.HasPrefix(r.URL.Path, UIBasePath)):
		s.handleUI(w, r)
		return
	case s.hasUI():
		http.Redirect(w, r, UIBasePath, http.StatusFound)
		return
	default:
		writeError(w, requestID, http.StatusNotFound, codeResourceNotFound, "resource not found")
		return
	}

	admitted, fullDiscovery := s.authenticate(r)
	if !admitted {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeError(w, requestID, http.StatusUnauthorized, codeAuthenticationRequired, "authentication required")
		return
	}
	ctx = context.WithValue(ctx, fullDiscoveryKey, fullDiscovery)
	r = r.WithContext(ctx)

	if isUnavailablePath(r.URL.Path) {
		writeError(w, requestID, http.StatusNotFound, codeCapabilityNotSupported, "resource is not supported by this engine")
		return
	}

	switch r.URL.Path {
	case "/api":
		if !isReadMethod(r.Method) {
			writeMethodNotAllowed(w, requestID, "GET, HEAD")
			return
		}
		s.handleDiscovery(w, r, fullDiscovery)
	case "/api/v1/version":
		if !isReadMethod(r.Method) {
			writeMethodNotAllowed(w, requestID, "GET, HEAD")
			return
		}
		s.handleVersion(w, r)
	case "/api/v1/capabilities":
		if !isReadMethod(r.Method) {
			writeMethodNotAllowed(w, requestID, "GET, HEAD")
			return
		}
		s.handleCapabilities(w, r)
	case "/api/v1/runtime":
		if !isReadMethod(r.Method) {
			writeMethodNotAllowed(w, requestID, "GET, HEAD")
			return
		}
		s.handleRuntime(w, r)
	case "/api/v1/runtime/traffic/history":
		s.handleTrafficHistory(w, r)
	case "/api/v1/groups":
		s.handleGroups(w, r)
	case "/api/v1/nodes":
		s.handleNodes(w, r)
	case "/api/v1/operations/reload", "/api/v1/operations/suspend", "/api/v1/operations/resume":
		s.handleStartOperation(w, r)
	default:
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/v1/groups/"):
			s.handleGroup(w, r)
		case strings.HasPrefix(r.URL.Path, "/api/v1/operations/"):
			s.handleOperation(w, r)
		case strings.HasPrefix(r.URL.Path, "/api/v1/nodes/"):
			s.handleNode(w, r)
		default:
			writeError(w, requestID, http.StatusNotFound, codeResourceNotFound, "resource not found")
		}
	}
}

// isAPIPath reports whether a request targets the control plane. Everything
// else is the frontend namespace or a navigation.
func isAPIPath(path string) bool {
	return path == "/api" || strings.HasPrefix(path, "/api/")
}

func isReadMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead
}

func writeMethodNotAllowed(w http.ResponseWriter, requestID, allow string) {
	w.Header().Set("Allow", allow)
	writeError(w, requestID, http.StatusMethodNotAllowed, codeMethodNotAllowed, "method is not allowed")
}

// unavailablePrefixes are contract resources this engine does not implement.
var unavailablePrefixes = []string{
	"/api/v1/config",
	"/api/v1/providers",
	"/api/v1/geodata",
	"/api/v1/rules",
	"/api/v1/dns",
	"/api/v1/flows",
	"/api/v1/connections",
	"/api/v1/probes",
	"/api/v1/events",
	"/api/v1/logs",
	"/api/v1/datapath",
	"/api/v1/runtime/outbounds",
	"/api/v1/runtime/memory",
	// Known contract resources with no implementation plan: answer
	// capability_not_supported instead of the generic resource_not_found.
	"/api/v1/runtime/settings",
	"/api/v1/routing/trace",
	"/api/v1/auth",
}

func isUnavailablePath(path string) bool {
	for _, prefix := range unavailablePrefixes {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}
