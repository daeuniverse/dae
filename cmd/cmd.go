package cmd

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/v2rayA/dae/common/consts"
	"github.com/v2rayA/dae/component/control"
	"github.com/v2rayA/dae/component/outbound"
	"github.com/v2rayA/dae/component/outbound/dialer"
	"github.com/v2rayA/dae/pkg/logger"
	"os"
	"os/signal"
	"syscall"
)

var (
	v       *viper.Viper
	Version = "unknown"
	verbose int
	rootCmd = &cobra.Command{
		Use:     "dae [flags] [command [argument ...]]",
		Short:   "dae is a lightweight and high-performance transparent proxy solution.",
		Long:    `dae is a lightweight and high-performance transparent proxy solution.`,
		Version: Version,
		Run: func(cmd *cobra.Command, args []string) {
			const (
				tproxyPort = 12345
				ifname     = "docker0"
			)
			logrus.SetLevel(logrus.DebugLevel)
			log := logger.NewLogger(2)
			log.Println("Running")

			d, err := dialer.NewFromLink(log, "socks5://localhost:1080#proxy")
			if err != nil {
				panic(err)
			}
			group := outbound.NewDialerGroup(log, "proxy",
				[]*dialer.Dialer{d},
				outbound.DialerSelectionPolicy{
					Policy: consts.DialerSelectionPolicy_MinAverage10Latencies,
				})
			t, err := control.NewControlPlane(log, []*outbound.DialerGroup{group}, `
#sip(172.17.0.2)->proxy
#mac("02:42:ac:11:00:02")->block
#ipversion(4)->proxy
#l4proto(tcp)->proxy
#ip(119.29.29.29) -> proxy
#ip(223.5.5.5) -> direct
ip(geoip:cn) -> direct

domain(full:google.com) && port(443) && l4proto(tcp) -> proxy

domain(geosite:cn, suffix:"ip.sb") -> direct
#ip("91.105.192.0/23","91.108.4.0/22","91.108.8.0/21","91.108.16.0/21","91.108.56.0/22","95.161.64.0/20","149.154.160.0/20","185.76.151.0/24")->proxy
#domain(geosite:category-scholar-!cn, geosite:category-scholar-cn)->direct
final: proxy
`)
			if err != nil {
				panic(err)
			}
			if err = t.BindLink(ifname); err != nil {
				panic(err)
			}
			sigs := make(chan os.Signal, 1)
			signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGKILL, syscall.SIGILL)
			go func() {
				if err := t.ListenAndServe(tproxyPort); err != nil {
					log.Errorln("ListenAndServe:", err)
					sigs <- nil
				}
			}()
			<-sigs
			if e := t.Close(); e != nil {
				log.Errorln("Close control plane:", err)
			}
		},
	}
)

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().CountVarP(&verbose, "verbose", "v", "verbose (-v, or -vv)")

	rootCmd.PersistentFlags().StringP("node", "n", "", "node share-link of your modern proxy")
	rootCmd.PersistentFlags().StringP("subscription", "s", "", "subscription-link of your modern proxy")
	rootCmd.PersistentFlags().Bool("noudp", false, "do not redirect UDP traffic, even though the proxy server supports")
	rootCmd.PersistentFlags().String("testnode", "true", "test the connectivity before connecting to the node")
	rootCmd.PersistentFlags().Bool("select", false, "manually select the node to connect from the subscription")
	//rootCmd.AddCommand(configCmd)
}

func NewLogger(verbose int) *logrus.Logger {
	log := logrus.New()

	var level logrus.Level
	switch verbose {
	case 0:
		level = logrus.WarnLevel
	case 1:
		level = logrus.InfoLevel
	default:
		level = logrus.TraceLevel
	}
	log.SetLevel(level)

	return log
}
