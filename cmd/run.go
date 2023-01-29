package cmd

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/v2rayA/dae/cmd/internal"
	"github.com/v2rayA/dae/component/control"
	"github.com/v2rayA/dae/config"
	"github.com/v2rayA/dae/pkg/config_parser"
	"github.com/v2rayA/dae/pkg/logger"
	"os"
	"os/signal"
	"syscall"
)

var (
	cfgFile string

	runCmd = &cobra.Command{
		Use:   "run",
		Short: "Run dae in the foreground",
		Run: func(cmd *cobra.Command, args []string) {
			if err := Run(); err != nil {
				logrus.Fatalln(err)
			}
		},
	}
)

func init() {
	runCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "config.dae", "config file")
}

func Run() (err error) {
	logrus.SetLevel(logrus.DebugLevel)
	log := logger.NewLogger(2)

	// Read config from --config cfgFile.
	param, err := readConfig()
	if err != nil {
		return fmt.Errorf("readConfig: %w", err)
	}

	// Require "sudo" if necessary.
	internal.AutoSu()

	// Resolve subscriptions to nodes.
	nodeList := make([]string, len(param.Node))
	copy(nodeList, param.Node)
	for _, sub := range param.Subscription {
		nodes, err := internal.ResolveSubscription(log, sub)
		if err != nil {
			log.Warnf(`failed to resolve subscription "%v": %v`, sub, err)
		}
		nodeList = append(nodeList, nodes...)
	}

	// New ControlPlane.
	t, err := control.NewControlPlane(
		log,
		nodeList,
		param.Group,
		&param.Routing,
		param.Global.DnsUpstream,
		param.Global.CheckUrl,
		param.Global.CheckInterval,
	)
	if err != nil {
		return err
	}

	// Bind to link.
	if err = t.BindLink(param.Global.LanInterface); err != nil {
		return err
	}

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

func readConfig() (params *config.Params, err error) {
	b, err := os.ReadFile(cfgFile)
	if err != nil {
		return nil, err
	}
	sections, err := config_parser.Parse(string(b))
	if err != nil {
		return nil, fmt.Errorf("\n%w", err)
	}
	if params, err = config.New(sections); err != nil {
		return nil, err
	}
	return params, nil
}
