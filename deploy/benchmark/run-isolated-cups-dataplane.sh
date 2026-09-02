#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY="$(cd -- "${SCRIPT_DIR}/../.." && pwd -P)"
NAMESPACE="lodestar-cups-data-$$"
BINARY="${CUPS_DATAPLANE_BENCH_BINARY:-${REPOSITORY}/bin/cups-dataplane-bench}"
ORIGINAL_RMEM="$(sysctl -n net.core.rmem_max)"
ORIGINAL_WMEM="$(sysctl -n net.core.wmem_max)"
NAMESPACE_CREATED=0
TUNED=0
CPU_LIST="${BENCH_CPU_LIST:-}"
GO_PROCS="${BENCH_GOMAXPROCS:-}"
BENCH_TIMEOUT="${CUPS_BENCH_TIMEOUT:-30s}"

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
if [[ ! "${BENCH_TIMEOUT}" =~ ^[1-9][0-9]*(s|m|h)$ ]]; then
	printf 'Invalid CUPS_BENCH_TIMEOUT: %s (use a positive whole number of s, m, or h)\n' "${BENCH_TIMEOUT}" >&2
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
for address in 10.254.91.1 10.254.91.2 10.254.92.1 10.254.92.2 10.254.94.1; do
	ip -n "${NAMESPACE}" addr add "${address}/32" dev lo
done

timeout --foreground --signal=INT --kill-after=10s "${BENCH_TIMEOUT}" \
	ip netns exec "${NAMESPACE}" "${EXEC_PREFIX[@]}" env "${CHILD_ENV[@]}" \
	"${BINARY}" "$@"
