#!/bin/bash
lan=docker0
wan=wlp5s0

sudo tc qdisc add dev $lan clsact > /dev/null 2>&1
sudo tc qdisc add dev $wan clsact > /dev/null 2>&1

set -ex

sudo rm -rf /sys/fs/bpf/tc/globals/*

# clang -fno-stack-protector -O2 -g -emit-llvm -c control/kern/tproxy.c -o - | llc -march=bpf -mcpu=v3 -mattr=+alu32 -filetype=obj -o foo.o
clang -O2 -g -Wall -Werror -c control/kern/tproxy.c -target bpf -D__TARGET_ARCH_x86 -o foo.o
sudo tc filter del dev $lan ingress
sudo tc filter del dev $lan egress
sudo tc filter del dev $wan ingress
sudo tc filter del dev $wan egress

sudo tc filter add dev $lan ingress bpf direct-action obj foo.o sec tc/ingress
# sudo tc filter add dev $wan ingress bpf direct-action obj foo.o sec tc/wan_ingress
# sudo tc filter add dev $wan egress bpf direct-action obj foo.o sec tc/wan_egress

sudo tc filter del dev $lan ingress
sudo tc filter del dev $lan egress
sudo tc filter del dev $wan ingress
sudo tc filter del dev $wan egress

exit 0