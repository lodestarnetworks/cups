#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY="$(cd -- "${SCRIPT_DIR}/../.." && pwd -P)"
NAMESPACE="lodestar-cups-ebpf-data-$$"
BINARY="${CUPS_DATAPLANE_BENCH_BINARY:-${REPOSITORY}/bin/cups-dataplane-bench}"
ORIGINAL_RMEM="$(sysctl -n net.core.rmem_max)"
ORIGINAL_WMEM="$(sysctl -n net.core.wmem_max)"
NAMESPACE_CREATED=0
TUNED=0
CPU_LIST="${BENCH_CPU_LIST:-}"
GO_PROCS="${BENCH_GOMAXPROCS:-}"
BENCH_TIMEOUT="${BENCH_TIMEOUT_SECONDS:-600}"

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
if [[ ! "${BENCH_TIMEOUT}" =~ ^[1-9][0-9]*$ ]] || (( BENCH_TIMEOUT > 3600 )); then
	printf 'BENCH_TIMEOUT_SECONDS must be between 1 and 3600.\n' >&2
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
CHILD_ENV=(SGW_NEXT_ISOLATED_CUPS_BENCH=1)
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
ip -n "${NAMESPACE}" addr add 10.254.94.1/32 dev lo

ip -n "${NAMESPACE}" link add lceacc type veth peer name lceenb
ip -n "${NAMESPACE}" link add lcecore type veth peer name lcepgw
ip -n "${NAMESPACE}" link set lceacc address 02:00:00:00:91:01
ip -n "${NAMESPACE}" link set lceenb address 02:00:00:00:91:02
ip -n "${NAMESPACE}" link set lcecore address 02:00:00:00:92:01
ip -n "${NAMESPACE}" link set lcepgw address 02:00:00:00:92:02
ip -n "${NAMESPACE}" addr add 10.254.91.1/32 dev lceacc
ip -n "${NAMESPACE}" addr add 10.254.91.2/32 dev lceenb
ip -n "${NAMESPACE}" addr add 10.254.92.1/32 dev lcecore
ip -n "${NAMESPACE}" addr add 10.254.92.2/32 dev lcepgw
ip -n "${NAMESPACE}" addr add 10.254.92.3/32 dev lcepgw
for interface in lceacc lceenb lcecore lcepgw; do
	ip -n "${NAMESPACE}" link set "${interface}" up
done

# All endpoints intentionally share one disposable namespace so one benchmark
# process can own both the SGW-U and kernel-GTP PGW-U. Remove only the two SGW-U
# local-table shortcuts and route them from their synthetic peer interfaces;
# otherwise Linux would deliver same-namespace traffic over loopback before it
# can reach either TCX ingress hook. The peer local routes remain for delivery
# after TCX redirect.
ip -n "${NAMESPACE}" route del table local local 10.254.91.1 dev lceacc
ip -n "${NAMESPACE}" route del table local local 10.254.92.1 dev lcecore
ip -n "${NAMESPACE}" route add 10.254.91.1/32 dev lceenb src 10.254.91.2
ip -n "${NAMESPACE}" route add 10.254.92.1/32 dev lcepgw src 10.254.92.2
ip -n "${NAMESPACE}" neigh add 10.254.91.1 lladdr 02:00:00:00:91:01 nud permanent dev lceenb
ip -n "${NAMESPACE}" neigh add 10.254.92.1 lladdr 02:00:00:00:92:01 nud permanent dev lcepgw
ip netns exec "${NAMESPACE}" sysctl -q -w net.ipv4.ip_nonlocal_bind=1
ip netns exec "${NAMESPACE}" sysctl -q -w net.ipv4.conf.all.rp_filter=0
ip netns exec "${NAMESPACE}" sysctl -q -w net.ipv4.conf.default.rp_filter=0
# The synthetic SGW-U and PGW-U deliberately share this namespace. Their
# outer addresses remain assigned to the opposite veth while local-table
# shortcuts are removed, so production-correct rp_filter=0 requires an
# explicit same-host source exception on both synthetic peers. These settings
# exist only for the lifetime of the disposable namespace.
ip netns exec "${NAMESPACE}" sysctl -q -w net.ipv4.conf.lcepgw.accept_local=1
ip netns exec "${NAMESPACE}" sysctl -q -w net.ipv4.conf.lceenb.accept_local=1

timeout --foreground --signal=INT --kill-after=3s "${BENCH_TIMEOUT}s" \
	ip netns exec "${NAMESPACE}" "${EXEC_PREFIX[@]}" env "${CHILD_ENV[@]}" \
	"${BINARY}" "$@" \
	--sgwu-backend tcx \
	--pgwu-policy \
	--access-interface lceacc --enb-interface lceenb \
	--core-interface lcecore --pgw-interface lcepgw
