//go:build linux

package dataplane

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.22.0 -tags linux pgwupolicy kernel_policy_bpf.c -- -O2 -g -Wall -Werror
