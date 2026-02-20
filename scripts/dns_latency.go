/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package main

import (
	"flag"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

func main() {
	server := flag.String("server", "127.0.0.1", "DNS server IP")
	port := flag.Int("port", 53, "DNS server port")
	count := flag.Int("count", 100, "Number of queries")
	domain := flag.String("domain", "google.com", "Domain to query")
	warmup := flag.Int("warmup", 5, "Warmup queries (to populate cache)")
	flag.Parse()

	addr := fmt.Sprintf("%s:%d", *server, *port)
	client := &dns.Client{
		Net:     "udp",
		Timeout: 5 * time.Second,
	}

	// Warmup - populate cache
	fmt.Printf("Warming up with %d queries...\n", *warmup)
	for i := 0; i < *warmup; i++ {
		m := new(dns.Msg)
		m.SetQuestion(*domain+".", dns.TypeA)
		_, _, _ = client.Exchange(m, addr)
	}
	time.Sleep(100 * time.Millisecond)

	// Actual test
	fmt.Printf("\nTesting cache hit latency (%d queries)...\n", *count)

	var totalLatency time.Duration
	var minLatency time.Duration = time.Hour
	var maxLatency time.Duration
	var successCount atomic.Int32

	// Test cached queries
	for i := 0; i < *count; i++ {
		m := new(dns.Msg)
		m.SetQuestion(*domain+".", dns.TypeA)
		
		start := time.Now()
		_, rtt, err := client.Exchange(m, addr)
		latency := time.Since(start)
		
		if err != nil {
			fmt.Printf("Query %d failed: %v\n", i+1, err)
			continue
		}
		
		successCount.Add(1)
		totalLatency += latency
		if latency < minLatency {
			minLatency = latency
		}
		if latency > maxLatency {
			maxLatency = latency
		}
		
		// Show first few results
		if i < 5 {
			fmt.Printf("Query %d: %v (RTT reported by client: %v)\n", i+1, latency, rtt)
		}
	}

	success := successCount.Load()
	if success > 0 {
		avgLatency := totalLatency / time.Duration(success)
		fmt.Printf("\n=== Cache Hit Results ===\n")
		fmt.Printf("Success: %d/%d\n", success, *count)
		fmt.Printf("Min: %v\n", minLatency)
		fmt.Printf("Max: %v\n", maxLatency)
		fmt.Printf("Avg: %v\n", avgLatency)
		fmt.Printf("Expected: < 5ms for local, < 50ms for LAN\n")
		
		if avgLatency > 100*time.Millisecond {
			fmt.Printf("\n⚠️  WARNING: Latency is too high for cache hit!\n")
			fmt.Printf("Possible causes:\n")
			fmt.Printf("  1. DNS upstream is slow (proxy latency)\n")
			fmt.Printf("  2. Cache not actually being hit\n")
			fmt.Printf("  3. Network latency between client and dae\n")
		} else if avgLatency < 5*time.Millisecond {
			fmt.Printf("\n✅ Latency is excellent!\n")
		}
	}

	// Test network RTT separately
	fmt.Printf("\n=== Network RTT Test (ping test) ===\n")
	pingStart := time.Now()
	conn, err := net.DialTimeout("udp", addr, 2*time.Second)
	if err != nil {
		fmt.Printf("Failed to connect: %v\n", err)
	} else {
		conn.Close()
		fmt.Printf("UDP dial time: %v\n", time.Since(pingStart))
	}
}
