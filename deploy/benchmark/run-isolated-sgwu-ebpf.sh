#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY="$(cd -- "${SCRIPT_DIR}/../.." && pwd -P)"
NAMESPACE="lodestar-sgwu-ebpf-$$"
BINARY="${SGWU_EBPF_BENCH_BINARY:-${REPOSITORY}/bin/sgwu-ebpf-bench}"
ORIGINAL_RMEM="$(sysctl -n net.core.rmem_max)"
ORIGINAL_WMEM="$(sysctl -n net.core.wmem_max)"
NAMESPACE_CREATED=0
TUNED=0
CPU_LIST="${BENCH_CPU_LIST:-}"
GO_PROCS="${BENCH_GOMAXPROCS:-}"

cleanup() {
	set +e
	if [[ "${NAMESPACE_CREATED}" == "1" ]]; then
		ip netns del "${NAMESPACE}" 2>/dev/null
	fi
	if [[ "${TUNED}" == "1" ]]; then
		sysctl -q -w "net.core.rmem_max=${ORIGINAL_RMEM}" 2>/dev/null
		sysctl -q -w "net.core.wmem_max=${ORIGINAL_WMEM}" 2>/dev/null
	fi
}
trap cleanup EXIT INT TERM

if (( EUID != 0 )); then
	printf 'Run this isolated benchmark as root.\n' >&2
	exit 1
fi
if [[ ! -f "${BINARY}" || ! -x "${BINARY}" || -L "${BINARY}" ]]; then
	printf 'Benchmark binary must be an executable regular file, not a symlink: %s\n' "${BINARY}" >&2
	exit 1
fi
if ip netns list | awk '{print $1}' | grep -Fxq "${NAMESPACE}"; then
	printf 'Refusing to reuse existing namespace %s\n' "${NAMESPACE}" >&2
	exit 1
fi

EXEC_PREFIX=()
if [[ -n "${CPU_LIST}" ]]; then
	if [[ ! "${CPU_LIST}" =~ ^[0-9,-]+$ ]]; then
		printf 'Invalid BENCH_CPU_LIST: %s\n' "${CPU_LIST}" >&2
		exit 1
	fi
	EXEC_PREFIX=(taskset --cpu-list "${CPU_LIST}")
fi
CHILD_ENV=(SGW_NEXT_ISOLATED_EBPF_BENCH=1)
if [[ -n "${GO_PROCS}" ]]; then
	if [[ ! "${GO_PROCS}" =~ ^[1-9][0-9]*$ ]]; then
		printf 'Invalid BENCH_GOMAXPROCS: %s\n' "${GO_PROCS}" >&2
		exit 1
	fi
	CHILD_ENV+=("GOMAXPROCS=${GO_PROCS}")
fi

if (( ORIGINAL_RMEM < 16777216 )); then
	sysctl -q -w net.core.rmem_max=16777216
	TUNED=1
fi
if (( ORIGINAL_WMEM < 16777216 )); then
	sysctl -q -w net.core.wmem_max=16777216
	TUNED=1
fi

ip netns add "${NAMESPACE}"
NAMESPACE_CREATED=1
ip -n "${NAMESPACE}" link set lo up
ip -n "${NAMESPACE}" link add lseacc type veth peer name lseenb
ip -n "${NAMESPACE}" link add lsecore type veth peer name lsepgw
ip -n "${NAMESPACE}" addr add 10.253.1.1/24 dev lseacc
ip -n "${NAMESPACE}" addr add 10.253.2.1/24 dev lsecore
for interface in lseacc lseenb lsecore lsepgw; do
	ip -n "${NAMESPACE}" link set "${interface}" up
done

timeout --foreground --signal=INT --kill-after=3s 75s \
	ip netns exec "${NAMESPACE}" "${EXEC_PREFIX[@]}" env "${CHILD_ENV[@]}" \
	"${BINARY}" "$@"
