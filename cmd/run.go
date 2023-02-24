package cmd

import (
	"fmt"
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
			param, includes, err := readConfig(cfgFile)
			if err != nil {
				logrus.Fatalln("readConfig:", err)
			}

			log := logger.NewLogger(param.Global.LogLevel, disableTimestamp)
			logrus.SetLevel(log.Level)

			log.Infof("Include config files: [%v]", strings.Join(includes, ", "))
			if err := Run(log, param); err != nil {
				logrus.Fatalln(err)
			}
		},
	}
)

func init() {
	runCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file")
	runCmd.PersistentFlags().BoolVarP(&disableTimestamp, "disable-timestamp", "", false, "disable timestamp")
}

func Run(log *logrus.Logger, param *config.Params) (err error) {

	/// Get tag -> nodeList mapping.
	tagToNodeList := map[string][]string{}
	if len(param.Node) > 0 {
		tagToNodeList[""] = append(tagToNodeList[""], param.Node...)
	}
	// Resolve subscriptions to nodes.
	for _, sub := range param.Subscription {
		tag, nodes, err := internal.ResolveSubscription(log, filepath.Dir(cfgFile), sub)
		if err != nil {
			log.Warnf(`failed to resolve subscription "%v": %v`, sub, err)
		}
		if len(nodes) > 0 {
			tagToNodeList[tag] = append(tagToNodeList[tag], nodes...)
		}
	}
	if len(tagToNodeList) == 0 {
		return fmt.Errorf("no node found, which could because all subscription resolving failed")
	}

	if len(param.Global.LanInterface) == 0 && len(param.Global.WanInterface) == 0 {
		return fmt.Errorf("LanInterface and WanInterface cannot both be empty")
	}

	// New ControlPlane.
	t, err := control.NewControlPlane(
		log,
		tagToNodeList,
		param.Group,
		&param.Routing,
		&param.Global,
		&param.Dns,
	)
	if err != nil {
		return err
	}

	// Call GC to release memory.
	runtime.GC()

	// Serve tproxy TCP/UDP server util signals.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGKILL, syscall.SIGILL)
	go func() {
		if err := t.ListenAndServe(param.Global.TproxyPort); err != nil {
			log.Errorln("ListenAndServe:", err)
			sigs <- nil
		}
	}()
	<-sigs
	if e := t.Close(); e != nil {
		return fmt.Errorf("close control plane: %w", e)
	}
	return nil
}

func readConfig(cfgFile string) (params *config.Params, includes []string, err error) {
	merger := config.NewMerger(cfgFile)
	sections, includes, err := merger.Merge()
	if err != nil {
		return nil, nil, err
	}
	if params, err = config.New(sections); err != nil {
		return nil, nil, err
	}
	return params, includes, nil
}
