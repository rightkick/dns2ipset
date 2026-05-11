package bpf

// `-no-strip` skips the post-compile `llvm-strip` step. Different Debian/
// Ubuntu releases ship llvm-strip under different (or no) unversioned
// symlinks; skipping is portable and only costs ~a few KB of unstripped
// debug info embedded in the .o, which is also useful when the BPF
// verifier rejects a program.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -cflags "-O2 -g -Wall -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu -include linux/bpf.h" Bpf c/dns2ipset.bpf.c
