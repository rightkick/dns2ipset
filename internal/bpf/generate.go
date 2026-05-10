package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu -include linux/bpf.h" Bpf c/dns2ipset.bpf.c
