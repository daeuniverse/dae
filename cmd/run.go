/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	"gopkg.in/natefinch/lumberjack.v2"

	_ "net/http/pprof"

	"github.com/daeuniverse/dae/cmd/internal"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
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
			if disableAuthSudo && os.Getuid() != 0 {
				logrus.Fatalln("Auto-sudo is disabled and current user is not root.")
			}
			// Require "sudo" if necessary.
			internal.AutoSu()

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
	c, err := newControlPlane(log, nil, nil, conf, externGeoDataDirs)
	if err != nil {
		return err
	}

	var pprofServer *http.Server
	if conf.Global.PprofPort != 0 {
		pprofAddr := fmt.Sprintf("localhost:%d", conf.Global.PprofPort)
		pprofServer = &http.Server{Addr: pprofAddr, Handler: nil}
		go pprofServer.ListenAndServe()
	}

	// Serve tproxy TCP/UDP server util signals.
	var listener *control.Listener
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGKILL, syscall.SIGILL, syscall.SIGUSR1, syscall.SIGUSR2)
	go func() {
		readyChan := make(chan bool, 1)
		go func() {
			<-readyChan
			sdnotify.Ready()
			if !disablePidFile {
				_ = os.WriteFile(PidFilePath, []byte(strconv.Itoa(os.Getpid())), 0644)
			}
			_ = os.WriteFile(SignalProgressFilePath, []byte{consts.ReloadDone}, 0644)
		}()
		control.GetDaeNetns().With(func() error {
			if listener, err = c.ListenAndServe(readyChan, conf.Global.TproxyPort); err != nil {
				log.Errorln("ListenAndServe:", err)
			}
			return err
		})
		sigs <- nil
	}()
	reloading := false
	reloadingErr := error(nil)
	isSuspend := false
	abortConnections := false
loop:
	for sig := range sigs {
		switch sig {
		case nil:
			if reloading {
				if listener == nil {
					// Failed to listen. Exit.
					break loop
				}
				// Serve.
				reloading = false
				log.Warnln("[Reload] Serve")
				readyChan := make(chan bool, 1)
				go func() {
					if err := c.Serve(readyChan, listener); err != nil {
						log.Errorln("ListenAndServe:", err)
					}
					sigs <- nil
				}()
				<-readyChan
				sdnotify.Ready()
				if reloadingErr == nil {
					_ = os.WriteFile(SignalProgressFilePath, append([]byte{consts.ReloadDone}, []byte("\nOK")...), 0644)
				} else {
					_ = os.WriteFile(SignalProgressFilePath, append([]byte{consts.ReloadError}, []byte("\n"+reloadingErr.Error())...), 0644)
				}
				log.Warnln("[Reload] Finished")
			} else {
				// Listening error.
				break loop
			}
		case syscall.SIGUSR2:
			isSuspend = true
			fallthrough
		case syscall.SIGUSR1:
			// Reload signal.
			if isSuspend {
				log.Warnln("[Reload] Received suspend signal; prepare to suspend")
			} else {
				log.Warnln("[Reload] Received reload signal; prepare to reload")
			}
			sdnotify.Reloading()
			_ = os.WriteFile(SignalProgressFilePath, []byte{consts.ReloadProcessing}, 0644)
			reloadingErr = nil

			// Load new config.
			abortConnections = os.Remove(AbortFile) == nil
			log.Warnln("[Reload] Load new config")
			var newConf *config.Config
			if isSuspend {
				isSuspend = false
				newConf, err = emptyConfig()
				if err != nil {
					log.WithFields(logrus.Fields{
						"err": err,
					}).Errorln("[Reload] Failed to reload")
					sdnotify.Ready()
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
					sdnotify.Ready()
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
			log.SetOutput(oldLogOutput) // FIXME: THIS IS A HACK.
			logrus.SetOutput(oldLogOutput)

			// New control plane.
			obj := c.EjectBpf()
			var dnsCache map[string]*control.DnsCache
			if conf.Dns.IpVersionPrefer == newConf.Dns.IpVersionPrefer {
				// Only keep dns cache when ip version preference not change.
				dnsCache = c.CloneDnsCache()
			}
			log.Warnln("[Reload] Load new control plane")
			newC, err := newControlPlane(log, obj, dnsCache, newConf, externGeoDataDirs)
			if err != nil {
				reloadingErr = err
				log.WithFields(logrus.Fields{
					"err": err,
				}).Errorln("[Reload] Failed to reload; try to roll back configuration")
				// Load last config back.
				newC, err = newControlPlane(log, obj, dnsCache, conf, externGeoDataDirs)
				if err != nil {
					sdnotify.Stopping()
					obj.Close()
					c.Close()
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
			reloading = true

			// Ready to close.
			if abortConnections {
				oldC.AbortConnections()
			}
			oldC.Close()

			if pprofServer != nil {
				pprofServer.Shutdown(context.Background())
				pprofServer = nil
			}
			if newConf.Global.PprofPort != 0 {
				pprofAddr := fmt.Sprintf("localhost:%d", conf.Global.PprofPort)
				pprofServer = &http.Server{Addr: pprofAddr, Handler: nil}
				go pprofServer.ListenAndServe()
			}
		case syscall.SIGHUP:
			// Ignore.
			continue
		default:
			log.Infof("Received signal: %v", sig.String())
			break loop
		}
	}
	defer os.Remove(PidFilePath)
	defer control.GetDaeNetns().Close()
	if e := c.Close(); e != nil {
		return fmt.Errorf("close control plane: %w", e)
	}
	return nil
}

func newControlPlane(log *logrus.Logger, bpf interface{}, dnsCache map[string]*control.DnsCache, conf *config.Config, externGeoDataDirs []string) (c *control.ControlPlane, err error) {
	// Deep copy to prevent modification.
	conf = deepcopy.Copy(conf).(*config.Config)

	/// Get tag -> nodeList mapping.
	tagToNodeList := map[string][]string{}
	if len(conf.Node) > 0 {
		for _, node := range conf.Node {
			tagToNodeList[""] = append(tagToNodeList[""], string(node))
		}
	}
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
			resp, err := client.Get(CheckNetworkLinks[i%len(CheckNetworkLinks)])
			if err != nil {
				log.Debugln("CheckNetwork:", err)
				var neterr net.Error
				if errors.As(err, &neterr) && neterr.Timeout() {
					// Do not sleep.
					continue
				}
				time.Sleep(epo)
				continue
			}
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 500 {
				break
			}
			log.Infof("Bad status: %v (%v)", resp.Status, resp.StatusCode)
			time.Sleep(epo)
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
	for _, sub := range conf.Subscription {
		tag, nodes, err := subscription.ResolveSubscription(log, &client, filepath.Dir(cfgFile), string(sub))
		if err != nil {
			log.Warnf(`failed to resolve subscription "%v": %v`, sub, err)
			resolvingfailed = true
		}
		if len(nodes) > 0 {
			tagToNodeList[tag] = append(tagToNodeList[tag], nodes...)
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

	c, err = control.NewControlPlane(
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
	// Call GC to release memory.
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
