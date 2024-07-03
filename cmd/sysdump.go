/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"bytes"
	"io/ioutil"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
    "time"

	"github.com/vishvananda/netlink"
	"github.com/spf13/cobra"
	"github.com/mholt/archiver/v3"
	"github.com/shirou/gopsutil/v4/net"
	"golang.org/x/sys/unix"
)

var (
	sysdumpCmd = &cobra.Command{
		Use:   "sysdump",
		Short: "To dump up system network config",
		Run: func(cmd *cobra.Command, args []string) {
			dumpNetworkInfo()
		},
	}
)

func dumpNetworkInfo() {
	tempDir, err := ioutil.TempDir("", "sysdump")
	if err != nil {
		fmt.Printf("Failed to create temp directory: %v\n", err)
		return
	}
	defer os.RemoveAll(tempDir)

	dumpRouting(tempDir)
	dumpNetInterfaces(tempDir)
	dumpSysctl(tempDir)
	dumpNetfilter(tempDir)
	dumpIPTables(tempDir)

	tarFile := fmt.Sprintf("sysdump.%d.tar.gz",time.Now().Unix())
	if err := archiver.Archive([]string{tempDir}, tarFile); err != nil {
		fmt.Printf("Failed to create tar archive: %v\n", err)
		return
	}

	fmt.Printf("System network information collected and saved to %s\n", tarFile)
}


// Translate scope enum into semantic words
func scopeToString(scope netlink.Scope) string {
	switch scope {
	case unix.RT_SCOPE_UNIVERSE:
		return "universe"
	case unix.RT_SCOPE_SITE:
		return "site"
	case unix.RT_SCOPE_LINK:
		return "link"
	case unix.RT_SCOPE_HOST:
		return "host"
	case unix.RT_SCOPE_NOWHERE:
		return "nowhere"
	default:
		return "unknown"
	}
}


// Translate protocol enum into semantic words
func protocolToString(proto int) string {
	switch proto {
	case unix.RTPROT_BABEL:
		return "babel"
	case unix.RTPROT_BGP:
		return "bgp"
	case unix.RTPROT_BIRD:
		return "bird"
	case unix.RTPROT_BOOT:
		return "boot"
	case unix.RTPROT_DHCP:
		return "dhcp"
	case unix.RTPROT_DNROUTED:
		return "dnrouted"
	case unix.RTPROT_EIGRP:
		return "eigrp"
	case unix.RTPROT_GATED:
		return "gated"
	case unix.RTPROT_ISIS:
		return "isis"
	case unix.RTPROT_KERNEL:
		return "kernel"
	case unix.RTPROT_MROUTED:
		return "mrouted"
	case unix.RTPROT_MRT:
		return "mrt"
	case unix.RTPROT_NTK:
		return "ntk"
	case unix.RTPROT_OSPF:
		return "ospf"
	case unix.RTPROT_RA:
		return "ra"
	case unix.RTPROT_REDIRECT:
		return "redirect"
	case unix.RTPROT_RIP:
		return "rip"
	case unix.RTPROT_STATIC:
		return "static"
	case unix.RTPROT_UNSPEC:
		return "unspec"
	case unix.RTPROT_XORP:
		return "xorp"
	case unix.RTPROT_ZEBRA:
		return "zebra"
	default:
		return "unknown"
	}
}

// Translate route.type enum into semantic words
func typeToString(typ int) string {
	switch typ {
	case unix.RTN_UNSPEC:
		return "unspec"
	case unix.RTN_UNICAST:
		return "unicast"
	case unix.RTN_LOCAL:
		return "local"
	case unix.RTN_BROADCAST:
		return "broadcast"
	case unix.RTN_ANYCAST:
		return "anycast"
	case unix.RTN_MULTICAST:
		return "multicast"
	case unix.RTN_BLACKHOLE:
		return "blackhole"
	case unix.RTN_UNREACHABLE:
		return "unreachable"
	case unix.RTN_PROHIBIT:
		return "prohibit"
	case unix.RTN_THROW:
		return "throw"
	case unix.RTN_NAT:
		return "nat"
	case unix.RTN_XRESOLVE:
		return "xresolve"
	default:
		return "unknown"
	}
}


func dumpRouting(outputDir string) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		fmt.Printf("Failed to get routing table: %v\n", err)
		return
	}

	var buffer bytes.Buffer
	buffer.WriteString("Routing Table:\n")
	for _, route := range routes {
		link, err := netlink.LinkByIndex(route.LinkIndex)
		if err != nil {
			fmt.Printf("Failed to get link by index: %v\n", err)
			continue
		}
		ifaceName := link.Attrs().Name

		routeStr := ""
		if route.Dst == nil {
			routeStr += "default"
		} else {
			routeStr += route.Dst.String()
		}

		if route.Gw != nil {
			routeStr += fmt.Sprintf(" via %s", route.Gw.String())
		}

		routeStr += fmt.Sprintf(" dev %s", ifaceName)

		if route.Scope != 0 {
			routeStr += fmt.Sprintf(" scope %d", scopeToString(route.Scope))
		}

		if route.Protocol != 0 {
			routeStr += fmt.Sprintf(" proto %d", protocolToString(route.Protocol))
		}

		if route.Type != 0 {
			routeStr += fmt.Sprintf(" type %d", typeToString(route.Type))
		}

		if route.Flags != 0 {
			routeStr += fmt.Sprintf(" flags %d", route.Flags)
		}

		buffer.WriteString(routeStr + "\n")
	}
	err = ioutil.WriteFile(filepath.Join(outputDir, "routing.txt"), buffer.Bytes(), 0644)
	if err != nil {
		fmt.Printf("Failed to write routing information to file: %v\n", err)
	}
}

func dumpNetInterfaces(outputDir string) {
	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Printf("Failed to get network interfaces: %v\n", err)
		return
	}

	var buffer bytes.Buffer
	buffer.WriteString("Network Interfaces:\n")
	for _, iface := range interfaces {
		buffer.WriteString(fmt.Sprintf("Name: %s, MTU: %d, HardwareAddr: %s, Flags: %v\n",
			iface.Name, iface.MTU, iface.HardwareAddr, iface.Flags))
		for _, addr := range iface.Addrs {
			buffer.WriteString(fmt.Sprintf("  Address: %s\n", addr.Addr))
		}
	}

	ioutil.WriteFile(filepath.Join(outputDir, "interfaces.txt"), buffer.Bytes(), 0644)
}


func dumpSysctl(outputDir string) {
	sysctlPath := "/proc/sys/net"
	var buffer bytes.Buffer

	err := filepath.Walk(sysctlPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Printf("Fail in filepath.Walk: %v\n", err)
		}

		if !info.IsDir() {
			value, err := ioutil.ReadFile(path)
			if err != nil {
				fmt.Printf("Fail in filepath.Walk: %v\n", err)
			}

			relativePath := strings.TrimPrefix(path, sysctlPath+"/")
			buffer.WriteString(fmt.Sprintf("%-60s = %s\n", relativePath, string(value)))
		}
		return nil
	})

	if err != nil {
		fmt.Printf("Failed to get sysctl settings: %v\n", err)
	}

	ioutil.WriteFile(filepath.Join(outputDir, "sysctl.txt"), buffer.Bytes(), 0644)
}

func dumpNetfilter(outputDir string) {
	cmd := exec.Command("nft", "list", "ruleset")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Failed to get nftables ruleset: %v\n", err)
		return
	}

	ioutil.WriteFile(filepath.Join(outputDir, "nftables.txt"), output, 0644)
}

func dumpIPTables(outputDir string) {
	iptables := exec.Command("iptables-save", "-c")
	output, err := iptables.CombinedOutput()
	if err != nil {
		fmt.Printf("Failed to get iptables: %v\n", err)
	} else {
		ioutil.WriteFile(filepath.Join(outputDir, "iptables.txt"), output, 0644)
	}

	ip6tables := exec.Command("ip6tables-save","-c")
	output, err = ip6tables.CombinedOutput()
	if err != nil {
		fmt.Printf("Failed to get ip6tables: %v\n", err)
	} else {
    ioutil.WriteFile(filepath.Join(outputDir, "ip6tables.txt"), output, 0644)
	}
}

func init() {
	rootCmd.AddCommand(sysdumpCmd)
}
