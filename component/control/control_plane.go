/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2022, v2rayA Organization <team@v2raya.org>
 */

package control

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/mzz2017/softwind/pool"
	"github.com/sirupsen/logrus"
	"github.com/v2rayA/dae/common"
	"github.com/v2rayA/dae/common/consts"
	"github.com/v2rayA/dae/component/outbound"
	"github.com/v2rayA/dae/component/outbound/dialer"
	"github.com/v2rayA/dae/component/routing"
	"github.com/v2rayA/dae/config"
	"github.com/v2rayA/dae/pkg/config_parser"
	internal "github.com/v2rayA/dae/pkg/ebpf_internal"
	"golang.org/x/sys/unix"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type ControlPlane struct {
	*ControlPlaneCore
	deferFuncs []func() error

	// TODO: add mutex?
	outbounds       []*outbound.DialerGroup
	outboundName2Id map[string]uint8

	SimulatedLpmTries  [][]netip.Prefix
	SimulatedDomainSet []DomainSet
	Final              string

	// mutex protects the dnsCache.
	mutex       sync.Mutex
	dnsCache    map[string]*dnsCache
	dnsUpstream netip.AddrPort
}

func NewControlPlane(
	log *logrus.Logger,
	nodes []string,
	groups []config.Group,
	routingA *config.Routing,
	dnsUpstream string,
	checkUrl string,
	checkInterval time.Duration,
	lanInterface []string,
	wanInterface []string,
) (c *ControlPlane, err error) {
	kernelVersion, e := internal.KernelVersion()
	if e != nil {
		return nil, fmt.Errorf("failed to get kernel version: %w", e)
	}
	// Must judge version from high to low to reduce the number of user upgrading kernel.
	if kernelVersion.Less(consts.ChecksumFeatureVersion) {
		return nil, fmt.Errorf("your kernel version %v does not support checksum related features; expect >=%v; upgrade your kernel and try again",
			kernelVersion.String(),
			consts.ChecksumFeatureVersion.String())
	}
	if len(wanInterface) > 0 && kernelVersion.Less(consts.CgSocketCookieFeatureVersion) {
		return nil, fmt.Errorf("your kernel version %v does not support bind to WAN; expect >=%v; remove wan_interface in config file and try again",
			kernelVersion.String(),
			consts.CgSocketCookieFeatureVersion.String())
	}
	if len(lanInterface) > 0 && kernelVersion.Less(consts.SkAssignFeatureVersion) {
		return nil, fmt.Errorf("your kernel version %v does not support bind to LAN; expect >=%v; remove lan_interface in config file and try again",
			kernelVersion.String(),
			consts.SkAssignFeatureVersion.String())
	}
	if kernelVersion.Less(consts.BasicFeatureVersion) {
		return nil, fmt.Errorf("your kernel version %v does not satisfy basic requirement; expect >=%v",
			c.kernelVersion.String(),
			consts.BasicFeatureVersion.String())
	}

	// Allow the current process to lock memory for eBPF resources.
	if err = rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("rlimit.RemoveMemlock:%v", err)
	}
	pinPath := filepath.Join(consts.BpfPinRoot, consts.AppName)
	os.MkdirAll(pinPath, 0755)

	// Load pre-compiled programs and maps into the kernel.
	log.Infof("Loading eBPF programs and maps into the kernel")
	var bpf bpfObjects
	var ProgramOptions ebpf.ProgramOptions
	if log.Level == logrus.PanicLevel {
		ProgramOptions = ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelBranch | ebpf.LogLevelStats,
			//LogLevel: ebpf.LogLevelInstruction | ebpf.LogLevelStats,
		}
	}

	// Trick. Replace the beams with rotten timbers to reduce the loading.
	var obj interface{} = &bpf // Bind to both LAN and WAN.
	if len(lanInterface) > 0 && len(wanInterface) == 0 {
		// Only bind LAN.
		obj = &bpfObjectsLan{}
	} else if len(lanInterface) == 0 && len(wanInterface) > 0 {
		// Only bind to WAN.
		// Trick. Replace the beams with rotten timbers.
		obj = &bpfObjectsWan{}
	}
retryLoadBpf:
	if err = loadBpfObjects(obj, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinPath,
		},
		Programs: ProgramOptions,
	}); err != nil {
		if errors.Is(err, ebpf.ErrMapIncompatible) {
			// Map property is incompatible. Remove the old map and try again.
			prefix := "use pinned map "
			_, after, ok := strings.Cut(err.Error(), prefix)
			if !ok {
				return nil, fmt.Errorf("loading objects: bad format: %w", err)
			}
			mapName, _, _ := strings.Cut(after, ":")
			_ = os.Remove(filepath.Join(pinPath, mapName))
			log.Infof("Incompatible new map format with existing map %v detected; removed the old one.", mapName)
			goto retryLoadBpf
		}
		// Get detailed log from ebpf.internal.(*VerifierError)
		if log.Level == logrus.FatalLevel {
			if v := reflect.Indirect(reflect.ValueOf(errors.Unwrap(errors.Unwrap(err)))); v.Kind() == reflect.Struct {
				if _log := v.FieldByName("Log"); _log.IsValid() {
					if strSlice, ok := _log.Interface().([]string); ok {
						log.Fatalln(strings.Join(strSlice, "\n"))
					}
				}
			}
		}
		return nil, fmt.Errorf("loading objects: %w", err)
	}
	if _, ok := obj.(*bpfObjects); !ok {
		// Reverse takeover.
		AssignBpfObjects(&bpf, obj)
	}

	// Write params.
	if err = bpf.ParamMap.Update(consts.DisableL4TxChecksumKey, consts.DisableL4ChecksumPolicy_SetZero, ebpf.UpdateAny); err != nil {
		return nil, err
	}
	if err = bpf.ParamMap.Update(consts.DisableL4RxChecksumKey, consts.DisableL4ChecksumPolicy_SetZero, ebpf.UpdateAny); err != nil {
		return nil, err
	}
	// Write tproxy (control plane) PID.
	if err = bpf.ParamMap.Update(consts.ControlPlaneOidKey, uint32(os.Getpid()), ebpf.UpdateAny); err != nil {
		return nil, err
	}
	// Write ip_proto to hdr_size map for IPv6 extension extraction.
	if err = bpf.IpprotoHdrsizeMap.Update(uint32(unix.IPPROTO_HOPOPTS), int32(-1), ebpf.UpdateAny); err != nil {
		return nil, err
	}
	if err = bpf.IpprotoHdrsizeMap.Update(uint32(unix.IPPROTO_ROUTING), int32(-1), ebpf.UpdateAny); err != nil {
		return nil, err
	}
	if err = bpf.IpprotoHdrsizeMap.Update(uint32(unix.IPPROTO_FRAGMENT), int32(4), ebpf.UpdateAny); err != nil {
		return nil, err
	}
	if err = bpf.IpprotoHdrsizeMap.Update(uint32(unix.IPPROTO_TCP), int32(-2), ebpf.UpdateAny); err != nil {
		return nil, err
	}
	if err = bpf.IpprotoHdrsizeMap.Update(uint32(unix.IPPROTO_UDP), int32(-2), ebpf.UpdateAny); err != nil {
		return nil, err
	}

	core := &ControlPlaneCore{
		log:           log,
		deferFuncs:    []func() error{bpf.Close},
		bpf:           &bpf,
		kernelVersion: &kernelVersion,
	}
	defer func() {
		if err != nil {
			_ = core.Close()
		}
	}()

	// Bind to links. Binding should be advance of dialerGroups to avoid un-routable old connection.
	for _, ifname := range lanInterface {
		if err = core.BindLan(ifname); err != nil {
			return nil, fmt.Errorf("BindLan: %v: %w", ifname, err)
		}
	}
	for _, ifname := range wanInterface {
		if err = core.BindWan(ifname); err != nil {
			return nil, fmt.Errorf("BindWan: %v: %w", ifname, err)
		}
	}

	// DialerGroups (outbounds).
	option := &dialer.GlobalOption{
		Log:           log,
		CheckUrl:      checkUrl,
		CheckInterval: checkInterval,
	}
	outbounds := []*outbound.DialerGroup{
		outbound.NewDialerGroup(option, consts.OutboundDirect.String(),
			[]*dialer.Dialer{dialer.NewDirectDialer(option, true)},
			outbound.DialerSelectionPolicy{
				Policy:     consts.DialerSelectionPolicy_Fixed,
				FixedIndex: 0,
			}),
		outbound.NewDialerGroup(option, consts.OutboundBlock.String(),
			[]*dialer.Dialer{dialer.NewBlockDialer(option)},
			outbound.DialerSelectionPolicy{
				Policy:     consts.DialerSelectionPolicy_Fixed,
				FixedIndex: 0,
			}),
	}

	// Filter out groups.
	dialerSet := outbound.NewDialerSetFromLinks(option, nodes)
	for _, group := range groups {
		// Parse policy.
		policy, err := outbound.NewDialerSelectionPolicyFromGroupParam(&group.Param)
		if err != nil {
			return nil, fmt.Errorf("failed to create group %v: %w", group.Name, err)
		}
		// Filter nodes.
		dialers, err := dialerSet.Filter(group.Param.Filter)
		if err != nil {
			return nil, fmt.Errorf(`failed to create group "%v": %w`, group.Name, err)
		}
		// Convert node links to dialers.
		log.Infof(`Group "%v" node list:`, group.Name)
		for _, d := range dialers {
			log.Infoln("\t" + d.Name())
			d.ActiveCheck()
		}
		if len(dialers) == 0 {
			log.Infoln("\t<Empty>")
		}
		// Create dialer group and append it to outbounds.
		dialerGroup := outbound.NewDialerGroup(option, group.Name, dialers, *policy)
		outbounds = append(outbounds, dialerGroup)
	}

	// Generate outboundName2Id from outbounds.
	if len(outbounds) > 0xff {
		return nil, fmt.Errorf("too many outbounds")
	}
	outboundName2Id := make(map[string]uint8)
	for i, o := range outbounds {
		outboundName2Id[o.Name] = uint8(i)
	}
	builder := NewRoutingMatcherBuilder(outboundName2Id, &bpf)

	// Routing.
	var rules []*config_parser.RoutingRule
	if rules, err = routing.ApplyRulesOptimizers(routingA.Rules,
		&routing.RefineFunctionParamKeyOptimizer{},
		&routing.DatReaderOptimizer{Logger: log},
		&routing.MergeAndSortRulesOptimizer{},
		&routing.DeduplicateParamsOptimizer{},
	); err != nil {
		return nil, fmt.Errorf("ApplyRulesOptimizers error:\n%w", err)
	}
	if log.IsLevelEnabled(logrus.DebugLevel) {
		var debugBuilder strings.Builder
		for _, rule := range rules {
			debugBuilder.WriteString(rule.String(true) + "\n")
		}
		log.Debugf("RoutingA:\n%vfinal: %v\n", debugBuilder.String(), routingA.Final)
	}
	if err = routing.ApplyMatcherBuilder(log, builder, rules, routingA.Final); err != nil {
		return nil, fmt.Errorf("ApplyMatcherBuilder: %w", err)
	}
	if err = builder.Build(); err != nil {
		return nil, fmt.Errorf("RoutingMatcherBuilder.Build: %w", err)
	}

	// DNS upstream.
	var dnsAddrPort netip.AddrPort
	if dnsUpstream != "" {
		dnsAddrPort, err = netip.ParseAddrPort(dnsUpstream)
		if err != nil {
			return nil, fmt.Errorf("failed to parse DNS upstream: \"%v\": %w", dnsUpstream, err)
		}
		dnsAddr16 := dnsAddrPort.Addr().As16()
		if err = bpf.DnsUpstreamMap.Update(consts.ZeroKey, bpfIpPort{
			Ip:   common.Ipv6ByteSliceToUint32Array(dnsAddr16[:]),
			Port: internal.Htons(dnsAddrPort.Port()),
		}, ebpf.UpdateAny); err != nil {
			return nil, err
		}
	} else {
		if err = bpf.DnsUpstreamMap.Update(consts.ZeroKey, bpfIpPort{
			Ip: [4]uint32{},
			// Zero port indicates no element, because bpf_map_lookup_elem cannot return 0 for map_type_array.
			Port: 0,
		}, ebpf.UpdateAny); err != nil {
			return nil, err
		}
	}

	return &ControlPlane{
		ControlPlaneCore:   core,
		deferFuncs:         nil,
		outbounds:          outbounds,
		outboundName2Id:    outboundName2Id,
		SimulatedLpmTries:  builder.SimulatedLpmTries,
		SimulatedDomainSet: builder.SimulatedDomainSet,
		Final:              routingA.Final,
		mutex:              sync.Mutex{},
		dnsCache:           make(map[string]*dnsCache),
		dnsUpstream:        dnsAddrPort,
	}, nil
}

func (c *ControlPlane) ListenAndServe(port uint16) (err error) {
	// Listen.
	var listenConfig = net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return dialer.TproxyControl(c)
		},
	}
	tcpListener, err := listenConfig.Listen(context.TODO(), "tcp", "[::1]:"+strconv.Itoa(int(port)))
	if err != nil {
		return fmt.Errorf("listenTCP: %w", err)
	}
	defer tcpListener.Close()
	packetConn, err := listenConfig.ListenPacket(context.TODO(), "udp", "[::1]:"+strconv.Itoa(int(port)))
	if err != nil {
		return fmt.Errorf("listenUDP: %w", err)
	}
	defer packetConn.Close()
	udpConn := packetConn.(*net.UDPConn)

	// Serve.

	if err := c.bpf.ParamMap.Update(consts.BigEndianTproxyPortKey, uint32(internal.Htons(port)), ebpf.UpdateAny); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	c.deferFuncs = append(c.deferFuncs, func() error {
		cancel()
		return nil
	})
	go func() {
		defer cancel()
		for {
			lconn, err := tcpListener.Accept()
			if err != nil {
				if !strings.Contains(err.Error(), "use of closed network connection") {
					c.log.Errorf("Error when accept: %v", err)
				}
				break
			}
			go func() {
				if err := c.handleConn(lconn); err != nil {
					c.log.Warnln("handleConn:", err)
				}
			}()
		}
	}()
	go func() {
		defer cancel()
		for {
			var buf [65535]byte
			var oob [120]byte // Size for original dest
			n, oobn, _, src, err := udpConn.ReadMsgUDPAddrPort(buf[:], oob[:])
			if err != nil {
				if !strings.Contains(err.Error(), "use of closed network connection") {
					c.log.Errorf("ReadFromUDPAddrPort: %v, %v", src.String(), err)
				}
				break
			}
			dst := RetrieveOriginalDest(oob[:oobn])
			if !dst.IsValid() {
				c.log.WithFields(logrus.Fields{
					"source": src.String(),
					"oob":    hex.EncodeToString(oob[:oobn]),
				}).Warnf("Failed to retrieve original dest")
				continue
			}
			newBuf := pool.Get(n)
			copy(newBuf, buf[:n])
			go func(data []byte, src, dst netip.AddrPort) {
				if e := c.handlePkt(newBuf, src, dst); e != nil {
					c.log.Warnln("handlePkt:", e)
				}
				pool.Put(newBuf)
			}(newBuf, src, dst)
		}
	}()
	<-ctx.Done()
	return nil
}

func (c *ControlPlane) Close() (err error) {
	// Invoke defer funcs in reverse order.
	for i := len(c.deferFuncs) - 1; i >= 0; i-- {
		if e := c.deferFuncs[i](); e != nil {
			// Combine errors.
			if err != nil {
				err = fmt.Errorf("%w; %v", err, e)
			} else {
				err = e
			}
		}
	}
	return c.ControlPlaneCore.Close()
}
