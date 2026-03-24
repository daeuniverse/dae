/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	"gopkg.in/natefinch/lumberjack.v2"

	_ "net/http/pprof"

	"github.com/daeuniverse/dae/cmd/internal"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/common/subscription"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/pkg/logger"
	"github.com/mohae/deepcopy"
	"github.com/okzk/sdnotify"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	PidFilePath            = "/var/run/dae.pid"
	SignalProgressFilePath = "/var/run/dae.progress"
)

var (
	CheckNetworkLinks = []string{
		"http://edge.microsoft.com/captiveportal/generate_204",
		"http://www.gstatic.com/generate_204",
		"http://www.qualcomm.cn/generate_204",
	}
)

func init() {
	runCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "Config file of dae.(required)")
	runCmd.PersistentFlags().StringVar(&logFile, "logfile", "", "Log file to write. Empty means writing to stdout and stderr.")
	runCmd.PersistentFlags().IntVar(&logFileMaxSize, "logfile-maxsize", 30, "Unit: MB. The maximum size in megabytes of the log file before it gets rotated.")
	runCmd.PersistentFlags().IntVar(&logFileMaxBackups, "logfile-maxbackups", 3, "The maximum number of old log files to retain.")
	runCmd.PersistentFlags().BoolVar(&disableTimestamp, "disable-timestamp", false, "Disable timestamp.")
	runCmd.PersistentFlags().BoolVar(&disablePidFile, "disable-pidfile", false, "Not generate /var/run/dae.pid.")
	runCmd.PersistentFlags().BoolVar(&disableAuthSudo, "disable-sudo", false, "Disable sudo prompt ,may cause startup failure due to insufficient permissions")
	rand.Shuffle(len(CheckNetworkLinks), func(i, j int) {
		CheckNetworkLinks[i], CheckNetworkLinks[j] = CheckNetworkLinks[j], CheckNetworkLinks[i]
	})
}

var (
	cfgFile           string
	logFile           string
	logFileMaxSize    int
	logFileMaxBackups int
	disableTimestamp  bool
	disablePidFile    bool
	disableAuthSudo   bool

	runCmd = &cobra.Command{
		Use:   "run",
		Short: "To run dae in the foreground.",
		Run: func(cmd *cobra.Command, args []string) {
			if cfgFile == "" {
				logrus.Fatalln("Argument \"--config\" or \"-c\" is required but not provided.")
			}
			if disableAuthSudo && os.Geteuid() != 0 {
				logrus.Fatalln("Auto-sudo is disabled and current user is not root.")
			}
			// Require "sudo" if necessary.
			if !disableAuthSudo {
				internal.AutoSu()
			}

			// Read config from --config cfgFile.
			conf, includes, err := readConfig(cfgFile)
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"err": err,
				}).Fatalln("Failed to read config")
			}

			var logOpts *lumberjack.Logger
			if logFile != "" {
				logOpts = &lumberjack.Logger{
					Filename:   logFile,
					MaxSize:    logFileMaxSize,
					MaxAge:     0,
					MaxBackups: logFileMaxBackups,
					LocalTime:  true,
					Compress:   true,
				}
			}
			log := logrus.New()
			logger.SetLogger(log, conf.Global.LogLevel, disableTimestamp, logOpts)
			logger.SetLogger(logrus.StandardLogger(), conf.Global.LogLevel, disableTimestamp, logOpts)

			log.Infof("Include config files: [%v]", strings.Join(includes, ", "))
			if err := Run(log, conf, []string{filepath.Dir(cfgFile)}); err != nil {
				log.Fatalln(err)
			}
		},
	}
)

func Run(log *logrus.Logger, conf *config.Config, externGeoDataDirs []string) (err error) {
	// Remove AbortFile at beginning.
	_ = os.Remove(AbortFile)

	// New ControlPlane.
	c, err := newControlPlane(context.Background(), log, nil, nil, conf, externGeoDataDirs)
	if err != nil {
		return err
	}

	var pprofServer *http.Server
	if conf.Global.PprofPort != 0 {
		pprofAddr := fmt.Sprintf("localhost:%d", conf.Global.PprofPort)
		pprofServer = &http.Server{Addr: pprofAddr, Handler: nil}
		go func() { _ = pprofServer.ListenAndServe() }()
	}

	// Serve tproxy TCP/UDP server util signals.
	var listener *control.Listener
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGILL, syscall.SIGUSR1, syscall.SIGUSR2)

	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	go func() {
		readyChan := make(chan bool, 1)
		go func() {
			if <-readyChan {
				_ = sdnotify.Ready()
				if !disablePidFile {
					_ = os.WriteFile(PidFilePath, []byte(strconv.Itoa(os.Getpid())), 0644)
				}
				_ = os.WriteFile(SignalProgressFilePath, []byte{consts.ReloadDone}, 0644)
			} else {
				log.Warn("Initialization failed; not signaling readiness to supervisor")
			}
		}()
		defer func() {
			select {
			case readyChan <- false:
			default:
			}
		}()
		if runErr := control.GetDaeNetns().WithRequired("listen and serve in dae netns", func() error {
			if listener, err = c.ListenAndServe(readyChan, conf.Global.TproxyPort); err != nil {
				log.Errorln("ListenAndServe:", err)
			}
			return err
		}); runErr != nil {
			log.Errorln("GetDaeNetns.With:", runErr)
		}
		sendSigExit(sigs)
	}()

	type reloadRequest struct {
		isSuspend bool
	}
	reloadReqs := make(chan reloadRequest, 1)

	var reloading atomic.Bool
	reloadingErr := error(nil)
	abortConnections := false

	go func() {
		for req := range reloadReqs {
			if req.isSuspend {
				log.Warnln("[Reload] Received suspend signal; prepare to suspend")
			} else {
				log.Warnln("[Reload] Received reload signal; prepare to reload")
			}
			_ = sdnotify.Reloading()
			_ = os.WriteFile(SignalProgressFilePath, []byte{consts.ReloadProcessing}, 0644)
			reloadingErr = nil

			// Load new config.
			abortConnections = os.Remove(AbortFile) == nil
			log.Warnln("[Reload] Load new config")
			var newConf *config.Config
			if req.isSuspend {
				newConf, err = emptyConfig()
				if err != nil {
					log.WithFields(logrus.Fields{
						"err": err,
					}).Errorln("[Reload] Failed to reload")
					_ = sdnotify.Ready()
					_ = os.WriteFile(SignalProgressFilePath, append([]byte{consts.ReloadError}, []byte("\n"+err.Error())...), 0644)
					continue
				}
				newConf.Global = deepcopy.Copy(conf.Global).(config.Global)
				newConf.Global.WanInterface = nil
				newConf.Global.LanInterface = nil
				newConf.Global.LogLevel = "warning"
			} else {
				var includes []string
				newConf, includes, err = readConfig(cfgFile)
				if err != nil {
					log.WithFields(logrus.Fields{
						"err": err,
					}).Errorln("[Reload] Failed to reload")
					_ = sdnotify.Ready()
					_ = os.WriteFile(SignalProgressFilePath, append([]byte{consts.ReloadError}, []byte("\n"+err.Error())...), 0644)
					continue
				}
				log.Infof("Include config files: [%v]", strings.Join(includes, ", "))
			}
			// New logger.
			oldLogOutput := log.Out
			log = logrus.New()
			logger.SetLogger(log, newConf.Global.LogLevel, disableTimestamp, nil)
			logger.SetLogger(logrus.StandardLogger(), newConf.Global.LogLevel, disableTimestamp, nil)
			log.SetOutput(oldLogOutput) // NOTE: Restore log output after creating new logger during reload.
			logrus.SetOutput(oldLogOutput)

			// New control plane.
			obj := c.EjectBpf()
			portChanged := conf.Global.TproxyPort != newConf.Global.TproxyPort
			if portChanged {
				log.Warnf("[Reload] Tproxy port changed from %d to %d; will perform a full reload of eBPF programs", conf.Global.TproxyPort, newConf.Global.TproxyPort)
				_ = obj.Close()
				obj = nil
				if listener != nil {
					_ = listener.Close()
					listener = nil
				}
			}

			var dnsCache map[string]*control.DnsCache
			if conf.Dns.IpVersionPrefer == newConf.Dns.IpVersionPrefer {
				// Only keep dns cache when ip version preference not change.
				dnsCache = c.CloneDnsCache()
			}
			// Stop old DNS listener before creating new one to avoid port conflicts
			if err := c.StopDNSListener(); err != nil {
				log.Warnf("[Reload] Failed to stop old DNS listener: %v", err)
			}

			log.Warnln("[Reload] Load new control plane")
			newC, err := newControlPlane(ctx, log, obj, dnsCache, newConf, externGeoDataDirs)
			if err != nil {
				reloadingErr = err
				log.WithFields(logrus.Fields{
					"err": err,
				}).Errorln("[Reload] Failed to reload; try to roll back configuration")
				// Load last config back.
				if portChanged {
					// If port changed, it's impossible to roll back easily because we already closed things.
					// But we can try to re-load the old configuration with fresh objects.
					log.Warnln("[Reload] Port already changed; attempting rollback with fresh eBPF objects")
					obj = nil
				}
				newC, err = newControlPlane(ctx, log, obj, dnsCache, conf, externGeoDataDirs)
				if err != nil {
					_ = sdnotify.Stopping()
					if obj != nil {
						_ = obj.Close()
					}
					_ = c.Close()
					log.WithFields(logrus.Fields{
						"err": err,
					}).Fatalln("[Reload] Failed to roll back configuration")
				}
				newConf = conf
				log.Errorln("[Reload] Last reload failed; rolled back configuration")
			} else {
				log.Warnln("[Reload] Stopped old control plane")
			}

			// Inject bpf objects into the new control plane life-cycle.
			newC.InjectBpf(obj)

			// Prepare new context.
			oldC := c
			c = newC
			conf = newConf
			reloading.Store(true)

			// Ready to close.
			if abortConnections {
				_ = oldC.AbortConnections()
			}
			_ = oldC.Close()

			if pprofServer != nil {
				pprofCtx, pprofCancel := context.WithTimeout(context.Background(), 2*time.Second)
				_ = pprofServer.Shutdown(pprofCtx)
				pprofCancel()
				pprofServer = nil
			}
			if newConf.Global.PprofPort != 0 {
				pprofAddr := fmt.Sprintf("localhost:%d", conf.Global.PprofPort)
				pprofServer = &http.Server{Addr: pprofAddr, Handler: nil}
				go func() { _ = pprofServer.ListenAndServe() }()
			}

			sendSigExit(sigs)
		}
	}()

	reloading.Store(false)
	reloadingErr = error(nil)
	abortConnections = false
loop:
	for sig := range sigs {
		switch sig {
		case nil:
			if reloading.Load() {
				if listener == nil {
					// Re-listen if port changed.
					log.Warnln("[Reload] Port changed; re-listening")
					readyChan := make(chan bool, 1)
					go func() {
						defer func() {
							select {
							case readyChan <- false:
							default:
							}
						}()
						if runErr := control.GetDaeNetns().WithRequired("listen and serve in dae netns", func() error {
							if listener, err = c.ListenAndServe(readyChan, conf.Global.TproxyPort); err != nil {
								log.Errorln("ListenAndServe:", err)
							}
							return err
						}); runErr != nil {
							log.Errorln("GetDaeNetns.With:", runErr)
						}
						sendSigExit(sigs)
					}()
					<-readyChan
					_ = sdnotify.Ready()
					if reloadingErr == nil {
						_ = os.WriteFile(SignalProgressFilePath, append([]byte{consts.ReloadDone}, []byte("\nOK")...), 0644)
					} else {
						_ = os.WriteFile(SignalProgressFilePath, append([]byte{consts.ReloadError}, []byte("\n"+reloadingErr.Error())...), 0644)
					}
					log.Warnln("[Reload] Finished (with port change)")
					reloading.Store(false)
					continue
				}
				// Serve.
				reloading.Store(false)
				log.Warnln("[Reload] Serve")
				readyChan := make(chan bool, 1)
				go func() {
					defer func() {
						select {
						case readyChan <- false:
						default:
						}
					}()
					if err := c.Serve(readyChan, listener); err != nil {
						log.Errorln("ListenAndServe:", err)
					}
					sendSigExit(sigs)
				}()
				<-readyChan
				_ = sdnotify.Ready()
				if reloadingErr == nil {
					_ = os.WriteFile(SignalProgressFilePath, append([]byte{consts.ReloadDone}, []byte("\nOK")...), 0644)
				} else {
					_ = os.WriteFile(SignalProgressFilePath, append([]byte{consts.ReloadError}, []byte("\n"+reloadingErr.Error())...), 0644)
				}
				log.Warnln("[Reload] Finished")
			} else if listener == nil {
				// Listening error.
				log.Errorln("[Critical] Listener failed; exiting")
				break loop
			}
		case syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGKILL:
			log.Infof("Received termination signal: %v", sig.String())
			break loop
		case syscall.SIGUSR2:
			select {
			case reloadReqs <- reloadRequest{isSuspend: true}:
			default:
				log.Warnln("[Reload] Last reload request still processing, ignore this one")
			}
		case syscall.SIGUSR1:
			select {
			case reloadReqs <- reloadRequest{isSuspend: false}:
			default:
				log.Warnln("[Reload] Last reload request still processing, ignore this one")
			}
		case syscall.SIGHUP:
			// Ignore.
			continue
		default:
			log.Infof("Received signal: %v", sig.String())
		}
	}
	defer func() {
		_ = sdnotify.Stopping()
		if pprofServer != nil {
			log.Infoln("Shutting down pprof server")
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = pprofServer.Shutdown(ctx)
			cancel()
		}
		_ = os.Remove(PidFilePath)
	}()

	// Restore network state immediately.
	if e := c.DetachBpfHooks(); e != nil {
		log.Warnf("detach BPF hooks: %v", e)
	}
	if e := control.GetDaeNetns().Close(); e != nil {
		log.Warnf("close dae netns: %v", e)
	}

	if e := c.AbortConnections(); e != nil {
		log.Warnf("abort connections: %v", e)
	}
	if e := c.Close(); e != nil {
		return fmt.Errorf("close control plane: %w", e)
	}
	return nil
}

func sendSigExit(sigs chan<- os.Signal) {
	select {
	case sigs <- nil:
	default:
	}
}

func newControlPlane(ctx context.Context, log *logrus.Logger, bpf any, dnsCache map[string]*control.DnsCache, conf *config.Config, externGeoDataDirs []string) (c *control.ControlPlane, err error) {
	// Deep copy to prevent modification.
	conf = deepcopy.Copy(conf).(*config.Config)

	/// Get tag -> nodeList mapping.
	tagToNodeList := map[string][]string{}
	// On initial startup (not reload), purge stale TC filters left by any previous process.
	if bpf == nil {
		control.PurgeStaleTCFilters(log)
	}
	if len(conf.Node) > 0 {
		for _, node := range conf.Node {
			tagToNodeList[""] = append(tagToNodeList[""], string(node))
		}
	}

	/// Init Direct Dialers.
	direct.InitDirectDialers(conf.Global.FallbackResolver)
	netutils.FallbackDns = netip.MustParseAddrPort(conf.Global.FallbackResolver)

	// Start timing the startup process
	startTime := time.Now()
	stageStart := startTime

	// Resolve subscriptions to nodes.
	resolvingfailed := false
	if !conf.Global.DisableWaitingNetwork {
		epo := 5 * time.Second
		client := http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (c net.Conn, err error) {
					conn, err := direct.SymmetricDirect.DialContext(ctx, common.MagicNetwork("tcp", conf.Global.SoMarkFromDae, conf.Global.Mptcp), addr)
					if err != nil {
						return nil, err
					}
					return &netproxy.FakeNetConn{
						Conn:  conn,
						LAddr: nil,
						RAddr: nil,
					}, nil
				},
			},
			Timeout: epo,
		}
		log.Infoln("Waiting for network...")
		for i := 0; ; i++ {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}

			resp, err := client.Get(CheckNetworkLinks[i%len(CheckNetworkLinks)])
			if err != nil {
				log.Debugln("CheckNetwork:", err)
				var neterr net.Error
				if errors.As(err, &neterr) && neterr.Timeout() {
					// Do not sleep.
					continue
				}
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(epo):
				}
				continue
			}
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 500 {
				break
			}
			log.Infof("Bad status: %v (%v)", resp.Status, resp.StatusCode)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(epo):
			}
		}
		log.Infoln("Network online.")
	}
	if len(conf.Subscription) > 0 {
		log.Infoln("Fetching subscriptions...")
	}
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (c net.Conn, err error) {
				conn, err := direct.SymmetricDirect.DialContext(ctx, common.MagicNetwork("tcp", conf.Global.SoMarkFromDae, conf.Global.Mptcp), addr)
				if err != nil {
					return nil, err
				}
				return &netproxy.FakeNetConn{
					Conn:  conn,
					LAddr: nil,
					RAddr: nil,
				}, nil
			},
		},
		Timeout: 30 * time.Second,
	}
	// Parallelize subscription resolution to improve startup performance.
	// Use a semaphore to limit concurrency and avoid overwhelming the network.
	type subscriptionResult struct {
		tag   string
		nodes []string
		err   error
		sub   config.KeyableString
	}
	numSubscriptions := len(conf.Subscription)
	if numSubscriptions > 0 {
		// Limit concurrency to 4 subscriptions at a time to avoid overwhelming network
		maxConcurrency := 4
		if numSubscriptions < maxConcurrency {
			maxConcurrency = numSubscriptions
		}
		sem := make(chan struct{}, maxConcurrency)
		results := make(chan subscriptionResult, numSubscriptions)

		for _, sub := range conf.Subscription {
			go func(s config.KeyableString) {
				sem <- struct{}{}        // Acquire semaphore
				defer func() { <-sem }() // Release semaphore

				tag, nodes, err := subscription.ResolveSubscription(log, &client, filepath.Dir(cfgFile), string(s))
				results <- subscriptionResult{
					tag:   tag,
					nodes: nodes,
					err:   err,
					sub:   s,
				}
			}(sub)
		}

		// Collect results
		for i := 0; i < numSubscriptions; i++ {
			result := <-results
			if result.err != nil {
				log.Warnf(`failed to resolve subscription "%v": %v`, result.sub, result.err)
				resolvingfailed = true
			}
			if len(result.nodes) > 0 {
				tagToNodeList[result.tag] = append(tagToNodeList[result.tag], result.nodes...)
			}
		}
		close(results)
		log.Infof("Subscriptions fetched in %v", time.Since(stageStart))
	}

	// Delete all files in persist.d that are not in tagToNodeList
	files, err := os.ReadDir(filepath.Join(filepath.Dir(cfgFile), "persist.d"))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	for _, file := range files {
		tag := strings.TrimSuffix(file.Name(), ".sub")
		if _, ok := tagToNodeList[tag]; !ok {
			err := os.Remove(filepath.Join(filepath.Dir(cfgFile), "persist.d", file.Name()))
			if err != nil {
				return nil, err
			}
		}
	}

	if len(tagToNodeList) == 0 {
		if resolvingfailed {
			log.Warnln("No node found because all subscription resolving failed.")
		} else {
			log.Warnln("No node found.")
		}
	}

	if len(conf.Global.LanInterface) == 0 && len(conf.Global.WanInterface) == 0 {
		log.Warnln("No interface to bind.")
	}

	if err = preprocessWanInterfaceAuto(conf); err != nil {
		return nil, err
	}

	// Start timing the control plane creation
	log.Infoln("Building control plane and routing rules...")
	stageStart = time.Now()
	c, err = control.NewControlPlaneWithContext(
		ctx,
		log,
		bpf,
		dnsCache,
		tagToNodeList,
		conf.Group,
		&conf.Routing,
		&conf.Global,
		&conf.Dns,
		externGeoDataDirs,
	)
	if err != nil {
		return nil, err
	}
	log.Infof("Control plane built in %v", time.Since(stageStart))
	log.Infof("Total startup time: %v", time.Since(startTime))
	// Call GC to release memory.
	log.Infoln("Control plane built successfully, running GC...")
	runtime.GC()

	return c, nil
}

func preprocessWanInterfaceAuto(params *config.Config) error {
	// preprocess "auto".
	ifs := make([]string, 0, len(params.Global.WanInterface)+2)
	for _, ifname := range params.Global.WanInterface {
		if ifname == "auto" {
			defaultIfs, err := common.GetDefaultIfnames()
			if err != nil {
				return fmt.Errorf("failed to convert 'auto': %w", err)
			}
			ifs = append(ifs, defaultIfs...)
		} else {
			ifs = append(ifs, ifname)
		}
	}
	params.Global.WanInterface = common.Deduplicate(ifs)
	return nil
}

func readConfig(cfgFile string) (conf *config.Config, includes []string, err error) {
	merger := config.NewMerger(cfgFile)
	sections, includes, err := merger.Merge()
	if err != nil {
		return nil, nil, err
	}
	if conf, err = config.New(sections); err != nil {
		return nil, nil, err
	}
	return conf, includes, nil
}

func emptyConfig() (conf *config.Config, err error) {
	sections, err := config_parser.Parse(`global{} routing{}`)
	if err != nil {
		return nil, err
	}
	if conf, err = config.New(sections); err != nil {
		return nil, err
	}
	return conf, nil
}

func init() {
	rootCmd.AddCommand(runCmd)
}
