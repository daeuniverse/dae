#!/bin/bash
dev=docker0

sudo tc qdisc add dev $dev clsact > /dev/null 2>&1

set -ex

sudo rm -rf /sys/fs/bpf/tc/globals/*

# clang -fno-stack-protector -O2 -g -emit-llvm -c component/control/kern/tproxy.c -o - | llc -march=bpf -mcpu=v3 -filetype=obj -o foo.o
clang -O2 -g -Wall -Werror -c component/control/kern/tproxy.c -target bpf -o foo.o
sudo tc filter del dev $dev ingress
sudo tc filter del dev $dev egress
sudo tc filter add dev $dev ingress bpf direct-action obj foo.o sec tc/ingress
sudo tc filter add dev $dev egress bpf direct-action obj foo.o sec tc/egress

exit 0