/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org> */

#ifndef __TPROXY_VERSION_H__
#define __TPROXY_VERSION_H__

/*
 * Kernel Version Compatibility Layer for tproxy.c
 * 
 * Background:
 * - Linux 6.1 and earlier kernels have strict stack depth limits (8 layers)
 * - Linux 6.2+ kernels improved the BPF verifier with better state management
 * - Using __noinline functions can exceed stack depth on 6.1
 * - Using __always_inline functions can cause state explosion on 6.12
 * 
 * Solution:
 * - Use __always_inline on kernels < 6.2 to avoid stack depth issues
 * - Use __noinline on kernels >= 6.2 to reduce code bloat
 * 
 * References:
 * - OSDI 2024: "Validating the eBPF Verifier via State Embedding"
 * - ACM 2024: "Multi-tier Optimization of eBPF Code"
 * - LWN 2024: "Modernizing BPF for the next 10 years"
 */

#include <linux/version.h>

/* 
 * IMPORTANT: LINUX_VERSION_CODE is unreliable in BPF CO-RE environment
 * 
 * Problem:
 * - LINUX_VERSION_CODE is a compile-time macro, determined at BPF compilation time
 * - BPF programs use CO-RE (Compile Once, Run Everywhere)
 * - The compiled BPF bytecode runs on different kernel versions than build time
 * - Using LINUX_VERSION_CODE for conditional compilation leads to wrong code paths
 *
 * Solution:
 * - Use conservative strategy: always use __always_inline
 * - This ensures compatibility with all kernel versions (including 6.1)
 * - Modern kernels (6.6+) can handle the code bloat from inlining
 * 
 * Why this works:
 * - Linux 6.1: Needs inlining to stay within 8-layer stack limit
 * - Linux 6.2+: Can handle inlined code (minor code bloat is acceptable)
 * - Trade-off: Slightly larger code size, but guaranteed compatibility
 */

/* 
 * Conservative function attribute for routing functions
 * 
 * Always use __always_inline to ensure compatibility with all kernel versions.
 * This is necessary because LINUX_VERSION_CODE is unreliable in BPF CO-RE.
 */
#define ROUTE_FUNC_ATTR __always_inline
#define ROUTE_DEBUG_MSG "Using __always_inline (conservative strategy for all kernels)"
/* 
 * Conservative function attribute for wan_egress functions
 * 
 * Phase 2 Optimization: do_tproxy_wan_egress() has a call depth of 5 layers
 * (do_tproxy_wan_egress -> parse_wan_egress_packet -> parse_transport -> parse_transport_fast/slow)
 * This is close to the 8-layer limit on Linux 6.1
 *
 * Always use __always_inline to ensure compatibility with Linux 6.1
 * and avoid potential stack depth issues.
 */
#define TPROXY_WAN_EGRESS_FUNC_ATTR __always_inline
#define TPROXY_WAN_EGRESS_DEBUG_MSG "Using __always_inline (conservative strategy)"

/* 
 * Note on parsing functions:
 * - Functions with shallow call depths (1-2 layers) are safe to keep as __noinline
 * - Only the main routing functions (route, do_tproxy_wan_egress) need __always_inline
 * - This conservative approach ensures Linux 6.1 compatibility
 */
#endif /* __TPROXY_VERSION_H__ */
