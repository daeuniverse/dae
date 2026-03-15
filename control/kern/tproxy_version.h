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
 * Kernel 6.2 introduced significant BPF verifier improvements:
 * - Better scalar value tracking
 * - Improved stack spill/fill analysis  
 * - Smarter state merging
 * - Can handle deeper call chains with noinline functions
 */
#define BPF_VERIFIER_IMPROVED_VERSION KERNEL_VERSION(6, 2, 0)

/* 
 * Conditional function attribute for routing functions
 * 
 * On older kernels (< 6.2): Use __always_inline to avoid stack depth issues
 * On newer kernels (>= 6.2): Use __noinline to reduce code bloat and avoid state explosion
 */
#if LINUX_VERSION_CODE < BPF_VERIFIER_IMPROVED_VERSION
  #define ROUTE_FUNC_ATTR __always_inline
  #define ROUTE_DEBUG_MSG "Using __always_inline for kernel < 6.2 (stack depth optimization)"
#else
  #define ROUTE_FUNC_ATTR __noinline
  #define ROUTE_DEBUG_MSG "Using __noinline for kernel >= 6.2 (verifier improved)"
#endif

/* 
 * Conditional function attribute for wan_egress functions
 * 
 * Phase 2 Optimization: do_tproxy_wan_egress() has a call depth of 5 layers
 * (do_tproxy_wan_egress -> parse_wan_egress_packet -> parse_transport -> parse_transport_fast/slow)
 * This is close to the 8-layer limit on Linux 6.1
 *
 * On older kernels (< 6.2): Use __always_inline to reduce stack depth
 * On newer kernels (>= 6.2): Use __noinline to maintain optimization
 */
#if LINUX_VERSION_CODE < BPF_VERIFIER_IMPROVED_VERSION
  #define TPROXY_WAN_EGRESS_FUNC_ATTR __always_inline
  #define TPROXY_WAN_EGRESS_DEBUG_MSG "Using __always_inline for do_tproxy_wan_egress on kernel < 6.2"
#else
  #define TPROXY_WAN_EGRESS_FUNC_ATTR __noinline
  #define TPROXY_WAN_EGRESS_DEBUG_MSG "Using __noinline for do_tproxy_wan_egress on kernel >= 6.2"
#endif

/* 
 * Conditional attribute for parsing functions (Phase 3 - optional)
 * 
 * These functions have shallow call depths (1-2 layers) and are safe to keep as __noinline
 * Only enable conditional compilation if deeper analysis shows it's needed
 */
#define TPROXY_PARSE_FUNC_ATTR __noinline  /* Keep as-is for now */

/* 
 * Fallback detection for runtime if compile-time detection unavailable
 * This can be used if LINUX_VERSION_CODE is not reliable
 */
#ifdef BPF_RUNTIME_KERNEL_CHECK
static __always_inline int kernel_supports_noinline_route(void)
{
	/* 
	 * Runtime detection logic could be added here
	 * For now, we rely on compile-time detection
	 */
	return LINUX_VERSION_CODE >= BPF_VERIFIER_IMPROVED_VERSION;
}
#endif

#endif /* __TPROXY_VERSION_H__ */
