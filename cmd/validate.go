/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	validateCmd = &cobra.Command{
		Use:   "validate",
		Short: "To validate dae config.",
		Run: func(cmd *cobra.Command, args []string) {
			if cfgFile == "" {
				fmt.Println("Argument \"--config\" or \"-c\" is required but not provided.")
				os.Exit(1)
			}
			// Read config from --config cfgFile.
			conf, _, err := readConfig(cfgFile)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			// Dry-run the rule validation the run path performs, so an illegal
			// rule set fails here (non-zero) instead of at daemon startup.
			log := logrus.New()
			if err := validateRoutingRules(log, conf, []string{filepath.Dir(cfgFile)}); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			// The main routing block above is only half of what the run path
			// validates: the DNS request/response routing has its own parser
			// chain (component/dns), and a typo there used to exit 0 here while
			// `dae run` refused to start. Same chain, no second copy of the
			// checks - see dns.ValidateRouting.
			if err := dns.ValidateRouting(log, &conf.Dns, []string{filepath.Dir(cfgFile)}); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}
)

func init() {
	rootCmd.AddCommand(validateCmd)

	validateCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file")
}

// validateRoutingRules is the rules-only dry-run of the run-time build chain.
// It reuses the same optimizer pipeline the control plane applies
// (control/control_plane.go: alias resolution, geoip/geosite expansion,
// merge+sort, param dedup) and the same rule lowering (component/routing's
// RulesBuilder fed by control.RegisterRoutingProgramParsers, the single
// registry the run path also uses), then resolves every rule and fallback
// outbound the way RoutingMatcherBuilder.outboundToId does. The only thing it
// does not do is touch BPF.
func validateRoutingRules(log *logrus.Logger, conf *config.Config, externGeoDataDirs []string) error {
	if conf == nil {
		return fmt.Errorf("nil config")
	}
	if log == nil {
		log = logrus.New()
	}
	program, err := routing.NewNormalizedProgram(conf.Routing.Rules, conf.Routing.Fallback,
		&routing.AliasOptimizer{},
		&routing.DatReaderOptimizer{Logger: log, LocationFinder: assets.NewLocationFinder(externGeoDataDirs)},
		&routing.MergeAndSortRulesOptimizer{},
		&routing.DeduplicateParamsOptimizer{},
	)
	if err != nil {
		return fmt.Errorf("ApplyRulesOptimizers error:\n%w", err)
	}

	// Same outbound namespace the control plane builds: the implicit direct
	// and block groups plus every configured group name.
	outboundNames := map[string]struct{}{
		consts.OutboundDirect.String(): {},
		consts.OutboundBlock.String():  {},
	}
	for _, group := range conf.Group {
		outboundNames[group.Name] = struct{}{}
	}
	resolveOutbound := func(name string) error {
		switch name {
		case consts.OutboundDirect.String(), consts.OutboundBlock.String(),
			consts.OutboundLogicalOr.String(), consts.OutboundLogicalAnd.String(),
			consts.OutboundMustRules.String(), consts.OutboundControlPlaneRouting.String():
			return nil
		}
		if _, ok := outboundNames[name]; !ok {
			return fmt.Errorf("outbound (group) %v not found; please define it in section \"group\"", strconv.Quote(name))
		}
		return nil
	}

	// The run-built parser registry is reused verbatim, so a routing function
	// added to the run path is validated here too; the mirror that used to live
	// in this file drifted silently by construction.
	err = program.Lower(log, func(b *routing.RulesBuilder) {
		control.RegisterRoutingProgramParsers(b, resolveOutbound)
	}, func(fallback config.FunctionOrString) error {
		fn, err := config.ParseFunctionOrString(fallback)
		if err != nil {
			return err
		}
		outbound, err := routing.ParseOutbound(fn)
		if err != nil {
			return err
		}
		return resolveOutbound(outbound.Name)
	})
	if err != nil {
		return fmt.Errorf("invalid routing rules: %w", err)
	}
	return nil
}
