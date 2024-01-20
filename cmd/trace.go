/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"os/signal"
	"syscall"

	"github.com/daeuniverse/dae/cmd/internal"
	"github.com/daeuniverse/dae/trace"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	IPv4, IPv6 bool
	L4Proto    string
	Port       int
	OutputFile string
)

func init() {
	traceCmd := &cobra.Command{
		Use:   "trace",
		Short: "To trace traffic",
		Run: func(cmd *cobra.Command, args []string) {
			internal.AutoSu()

			if IPv4 && IPv6 {
				logrus.Fatalln("IPv4 and IPv6 cannot be set at the same time")
			}
			if !IPv4 && !IPv6 {
				IPv4 = true
			}
			IPVersion := 4
			if IPv6 {
				IPVersion = 6
			}

			var L4ProtoNo uint16
			switch L4Proto {
			case "tcp":
				L4ProtoNo = syscall.IPPROTO_TCP
			case "udp":
				L4ProtoNo = syscall.IPPROTO_UDP
			default:
				logrus.Fatalf("Unknown L4 protocol: %s\n", L4Proto)
			}

			ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()
			if err := trace.StartTrace(ctx, IPVersion, L4ProtoNo, Port, OutputFile); err != nil {
				logrus.Fatalln(err)
			}
		},
	}

	traceCmd.PersistentFlags().BoolVarP(&IPv4, "ipv4", "4", false, "Capture IPv4 traffic")
	traceCmd.PersistentFlags().BoolVarP(&IPv6, "ipv6", "6", false, "Capture IPv6 traffic")
	traceCmd.PersistentFlags().StringVarP(&L4Proto, "l4-proto", "p", "tcp", "Layer 4 protocol")
	traceCmd.PersistentFlags().IntVarP(&Port, "port", "P", 80, "Port")
	traceCmd.PersistentFlags().StringVarP(&OutputFile, "output", "o", "/dev/stdout", "Output file")

	rootCmd.AddCommand(traceCmd)
}
