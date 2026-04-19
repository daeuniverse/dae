package cmd

import "github.com/sirupsen/logrus"

func shutdownAfterSignal(
	log *logrus.Logger,
	listener signalShutdownListener,
	c signalShutdownControlPlane,
	netns signalShutdownNetns,
	fastExit bool,
) error {
	return shutdownAfterSignalWithHandoff(log, listener, c, netns, fastExit, nil)
}
