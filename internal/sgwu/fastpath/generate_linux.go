//go:build linux

package fastpath

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.22.0 -tags linux bpf fastpath_bpf.c -- -O2 -g -Wall -Werror
