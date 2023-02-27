package cmd

import (
	"fmt"
	"github.com/mohae/deepcopy"
	"github.com/okzk/sdnotify"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/v2rayA/dae/cmd/internal"
	"github.com/v2rayA/dae/config"
	"github.com/v2rayA/dae/control"
	"github.com/v2rayA/dae/pkg/logger"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

var (
	cfgFile          string
	disableTimestamp bool

	runCmd = &cobra.Command{
		Use:   "run",
		Short: "Run dae in the foreground",
		Run: func(cmd *cobra.Command, args []string) {
			if cfgFile == "" {
				logrus.Fatalln("Argument \"--config\" or \"-c\" is required but not provided.")
			}

			// Require "sudo" if necessary.
			internal.AutoSu()

			// Read config from --config cfgFile.
			conf, includes, err := readConfig(cfgFile)
			if err != nil {
				logrus.Fatalln("readConfig:", err)
			}

			log := logger.NewLogger(conf.Global.LogLevel, disableTimestamp)
			logrus.SetLevel(log.Level)

			log.Infof("Include config files: [%v]", strings.Join(includes, ", "))
			if err := Run(log, conf); err != nil {
				logrus.Fatalln(err)
			}
		},
	}
)

func init() {
	runCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file")
	runCmd.PersistentFlags().BoolVarP(&disableTimestamp, "disable-timestamp", "", false, "disable timestamp")
}

func Run(log *logrus.Logger, conf *config.Config) (err error) {

	// New ControlPlane.
	c, err := newControlPlane(log, nil, conf)
	if err != nil {
		return err
	}

	// Serve tproxy TCP/UDP server util signals.
	var listener *control.Listener
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGKILL, syscall.SIGILL, syscall.SIGUSR1)
	go func() {
		readyChan := make(chan bool, 1)
		go func() {
			<-readyChan
			sdnotify.Ready()
		}()
		if listener, err = c.ListenAndServe(readyChan, conf.Global.TproxyPort); err != nil {
			log.Errorln("ListenAndServe:", err)
		}
		sigs <- nil
	}()
	reloading := false
loop:
	for sig := range sigs {
		switch sig {
		case nil:
			if reloading {
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
				log.Warnln("[Reload] Finished")
			} else {
				break loop
			}
		case syscall.SIGUSR1:
			// Reload signal.
			sdnotify.Reloading()
			log.Warnln("[Reload] Received reload signal; prepare to reload")
			obj := c.EjectBpf()
			log.Warnln("[Reload] Load new control plane")
			newC, err := newControlPlane(log, obj, conf)
			if err != nil {
				log.WithFields(logrus.Fields{
					"err": err,
				}).Errorln("failed to reload")
				sdnotify.Ready()
				continue
			}
			log.Warnln("[Reload] Stopped old control plane")
			c.Close()
			c = newC
			reloading = true
		default:
			break loop
		}
	}
	if e := c.Close(); e != nil {
		return fmt.Errorf("close control plane: %w", e)
	}
	return nil
}

func newControlPlane(log *logrus.Logger, bpf interface{}, conf *config.Config) (c *control.ControlPlane, err error) {
	/// Get tag -> nodeList mapping.
	tagToNodeList := map[string][]string{}
	if len(conf.Node) > 0 {
		for _, node := range conf.Node {
			tagToNodeList[""] = append(tagToNodeList[""], string(node))
		}
	}
	// Resolve subscriptions to nodes.
	for _, sub := range conf.Subscription {
		tag, nodes, err := internal.ResolveSubscription(log, filepath.Dir(cfgFile), string(sub))
		if err != nil {
			log.Warnf(`failed to resolve subscription "%v": %v`, sub, err)
		}
		if len(nodes) > 0 {
			tagToNodeList[tag] = append(tagToNodeList[tag], nodes...)
		}
	}
	if len(tagToNodeList) == 0 {
		return nil, fmt.Errorf("no node found, which could because all subscription resolving failed")
	}

	if len(conf.Global.LanInterface) == 0 && len(conf.Global.WanInterface) == 0 {
		return nil, fmt.Errorf("LanInterface and WanInterface cannot both be empty")
	}

	// Deep copy a conf to avoid modification.
	conf = deepcopy.Copy(conf).(*config.Config)
	c, err = control.NewControlPlane(
		log,
		bpf,
		tagToNodeList,
		conf.Group,
		&conf.Routing,
		&conf.Global,
		&conf.Dns,
	)
	if err != nil {
		return nil, err
	}
	// Call GC to release memory.
	runtime.GC()

	return c, nil
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
