/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __PKT_CLS_DEFS_H__
#define __PKT_CLS_DEFS_H__

#define TC_COOKIE_MAX_SIZE 16

/* Action attributes */

/* See other TCA_ACT_FLAGS_ * flags in include/net/act_api.h. */
#define TCA_ACT_FLAGS_NO_PERCPU_STATS                                          \
  (1 << 0)                             /* Don't use percpu allocator for       \
                                        * actions stats.                       \
                                        */
#define TCA_ACT_FLAGS_SKIP_HW (1 << 1) /* don't offload action to HW */
#define TCA_ACT_FLAGS_SKIP_SW (1 << 2) /* don't use action in SW */

/* tca HW stats type
 * When user does not pass the attribute, he does not care.
 * It is the same as if he would pass the attribute with
 * all supported bits set.
 * In case no bits are set, user is not interested in getting any HW statistics.
 */
#define TCA_ACT_HW_STATS_IMMEDIATE                                             \
  (1 << 0) /* Means that in dump, user                                         \
            * gets the current HW stats                                        \
            * state from the device                                            \
            * queried at the dump time.                                        \
            */
#define TCA_ACT_HW_STATS_DELAYED                                               \
  (1 << 1) /* Means that in dump, user gets                                    \
            * HW stats that might be out of date                               \
            * for some time, maybe couple of                                   \
            * seconds. This is the case when                                   \
            * driver polls stats updates                                       \
            * periodically or when it gets async                               \
            * stats update from the device.                                    \
            */

#define TCA_ACT_MAX __TCA_ACT_MAX
#define TCA_OLD_COMPAT (TCA_ACT_MAX + 1)
#define TCA_ACT_MAX_PRIO 32
#define TCA_ACT_BIND 1
#define TCA_ACT_NOBIND 0
#define TCA_ACT_UNBIND 1
#define TCA_ACT_NOUNBIND 0
#define TCA_ACT_REPLACE 1
#define TCA_ACT_NOREPLACE 0

#define TC_ACT_UNSPEC (-1)
#define TC_ACT_OK 0
#define TC_ACT_RECLASSIFY 1
#define TC_ACT_SHOT 2
#define TC_ACT_PIPE 3
#define TC_ACT_STOLEN 4
#define TC_ACT_QUEUED 5
#define TC_ACT_REPEAT 6
#define TC_ACT_REDIRECT 7
#define TC_ACT_TRAP 8
/* For hw path, this means "trap to cpu"
 * and don't further process the frame
 * in hardware. For sw path, this is
 * equivalent of TC_ACT_STOLEN - drop
 * the skb and act like everything
 * is alright.
 */
#define TC_ACT_VALUE_MAX TC_ACT_TRAP

/* There is a special kind of actions called "extended actions",
 * which need a value parameter. These have a local opcode located in
 * the highest nibble, starting from 1. The rest of the bits
 * are used to carry the value. These two parts together make
 * a combined opcode.
 */
#define __TC_ACT_EXT_SHIFT 28
#define __TC_ACT_EXT(local) ((local) << __TC_ACT_EXT_SHIFT)
#define TC_ACT_EXT_VAL_MASK ((1 << __TC_ACT_EXT_SHIFT) - 1)
#define TC_ACT_EXT_OPCODE(combined) ((combined) & (~TC_ACT_EXT_VAL_MASK))
#define TC_ACT_EXT_CMP(combined, opcode) (TC_ACT_EXT_OPCODE(combined) == opcode)

#define TC_ACT_JUMP __TC_ACT_EXT(1)
#define TC_ACT_GOTO_CHAIN __TC_ACT_EXT(2)
#define TC_ACT_EXT_OPCODE_MAX TC_ACT_GOTO_CHAIN

/* These macros are put here for binary compatibility with userspace apps that
 * make use of them. For kernel code and new userspace apps, use the TCA_ID_*
 * versions.
 */
#define TCA_ACT_GACT 5
#define TCA_ACT_IPT 6
#define TCA_ACT_PEDIT 7
#define TCA_ACT_MIRRED 8
#define TCA_ACT_NAT 9
#define TCA_ACT_XT 10
#define TCA_ACT_SKBEDIT 11
#define TCA_ACT_VLAN 12
#define TCA_ACT_BPF 13
#define TCA_ACT_CONNMARK 14
#define TCA_ACT_SKBMOD 15
#define TCA_ACT_CSUM 16
#define TCA_ACT_TUNNEL_KEY 17
#define TCA_ACT_SIMP 22
#define TCA_ACT_IFE 25
#define TCA_ACT_SAMPLE 26

#endif