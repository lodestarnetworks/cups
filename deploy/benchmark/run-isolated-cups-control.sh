#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY="$(cd -- "${SCRIPT_DIR}/../.." && pwd -P)"
NAMESPACE="lodestar-cups-control-$$"
BINARY="${CUPS_CONTROL_BENCH_BINARY:-${REPOSITORY}/bin/cups-control-bench}"
ORIGINAL_RMEM="$(sysctl -n net.core.rmem_max)"
ORIGINAL_WMEM="$(sysctl -n net.core.wmem_max)"
NAMESPACE_CREATED=0
TUNED=0
CPU_LIST="${BENCH_CPU_LIST:-}"
GO_PROCS="${BENCH_GOMAXPROCS:-}"
FAULT_PROFILE="${BENCH_CONTROL_FAULT_PROFILE:-none}"

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

case "${FAULT_PROFILE}" in
	none|loss-duplicate-reorder) ;;
	*)
		printf 'Invalid BENCH_CONTROL_FAULT_PROFILE: %s\n' "${FAULT_PROFILE}" >&2
		exit 1
		;;
esac

CHILD_ENV=(SGW_NEXT_ISOLATED_CONTROL_BENCH=1 "SGW_NEXT_CONTROL_FAULT_PROFILE=${FAULT_PROFILE}")
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
for address in \
	10.254.101.1 10.254.101.2 10.254.102.1 10.254.102.2 \
	10.254.103.1 10.254.103.2 10.254.104.1 10.254.104.2 \
	10.254.105.1 10.254.105.2 10.254.106.1 10.254.106.2; do
	ip -n "${NAMESPACE}" addr add "${address}/32" dev lo
done

if [[ "${FAULT_PROFILE}" == "loss-duplicate-reorder" ]]; then
	ip netns exec "${NAMESPACE}" tc qdisc replace dev lo root netem \
		delay 2ms 1ms 25% loss 2% duplicate 1% reorder 25% 50%
fi

timeout --foreground --signal=INT --kill-after=5s 180s \
	ip netns exec "${NAMESPACE}" "${EXEC_PREFIX[@]}" env "${CHILD_ENV[@]}" \
	"${BINARY}" "$@"
