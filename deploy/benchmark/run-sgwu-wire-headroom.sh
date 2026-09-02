#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY="$(cd -- "${SCRIPT_DIR}/../.." && pwd -P)"
HEADROOM_NAMESPACE="lodestar-sgwu-headroom-$$"
HEADROOM_SOURCE_INTERFACE="lswgen"
HEADROOM_SINK_INTERFACE="lswnull"
HEADROOM_SOURCE_MAC="${WIRE_GENERATOR_MAC:-02:4c:53:57:00:03}"
HEADROOM_SINK_MAC="${WIRE_ACCESS_MAC:-02:4c:53:57:00:01}"
HEADROOM_BINARY="${SGWU_WIRE_BENCH_BINARY:-${REPOSITORY}/bin/sgwu-wire-bench}"
HEADROOM_CPU_LIST="${BENCH_CPU_LIST:-}"
HEADROOM_GO_PROCS="${BENCH_GOMAXPROCS:-}"
HEADROOM_ORIGINAL_WMEM="$(sysctl -n net.core.wmem_max)"
HEADROOM_NAMESPACE_CREATED=0
HEADROOM_TUNED=0

cleanup() {
	set +e
	if [[ "${HEADROOM_NAMESPACE_CREATED}" == "1" ]]; then
		ip netns del "${HEADROOM_NAMESPACE}" 2>/dev/null
	fi
	if [[ "${HEADROOM_TUNED}" == "1" ]]; then
		sysctl -q -w "net.core.wmem_max=${HEADROOM_ORIGINAL_WMEM}" 2>/dev/null
	fi
}
trap cleanup EXIT INT TERM HUP

if (( EUID != 0 )); then
	printf 'Run the generator-headroom wrapper as root.\n' >&2
	exit 1
fi
if [[ ! -f "${HEADROOM_BINARY}" || ! -x "${HEADROOM_BINARY}" || -L "${HEADROOM_BINARY}" ]]; then
	printf 'Benchmark binary must be an executable regular file, not a symlink: %s\n' "${HEADROOM_BINARY}" >&2
	exit 1
fi

HEADROOM_EXEC_PREFIX=()
if [[ -n "${HEADROOM_CPU_LIST}" ]]; then
	if [[ ! "${HEADROOM_CPU_LIST}" =~ ^[0-9,-]+$ ]]; then
		printf 'Invalid BENCH_CPU_LIST: %s\n' "${HEADROOM_CPU_LIST}" >&2
		exit 1
	fi
	HEADROOM_EXEC_PREFIX=(taskset --cpu-list "${HEADROOM_CPU_LIST}")
fi
HEADROOM_CHILD_ENV=("SGW_NEXT_SGWU_WIRE_BENCH=1" "BENCH_CPU_LIST=${HEADROOM_CPU_LIST}")
if [[ -n "${HEADROOM_GO_PROCS}" ]]; then
	if [[ ! "${HEADROOM_GO_PROCS}" =~ ^[1-9][0-9]*$ ]]; then
		printf 'Invalid BENCH_GOMAXPROCS: %s\n' "${HEADROOM_GO_PROCS}" >&2
		exit 1
	fi
	HEADROOM_CHILD_ENV+=("GOMAXPROCS=${HEADROOM_GO_PROCS}")
fi

if (( HEADROOM_ORIGINAL_WMEM < 134217728 )); then
	sysctl -q -w net.core.wmem_max=134217728
	HEADROOM_TUNED=1
fi

ip netns add "${HEADROOM_NAMESPACE}"
HEADROOM_NAMESPACE_CREATED=1
ip link add "${HEADROOM_SOURCE_INTERFACE}" address "${HEADROOM_SOURCE_MAC}" type veth \
	peer name "${HEADROOM_SINK_INTERFACE}" address "${HEADROOM_SINK_MAC}"
ip link set "${HEADROOM_SOURCE_INTERFACE}" netns "${HEADROOM_NAMESPACE}"
ip link set "${HEADROOM_SINK_INTERFACE}" netns "${HEADROOM_NAMESPACE}"
ip -n "${HEADROOM_NAMESPACE}" link set lo up
ip -n "${HEADROOM_NAMESPACE}" link set "${HEADROOM_SOURCE_INTERFACE}" up
ip -n "${HEADROOM_NAMESPACE}" link set "${HEADROOM_SINK_INTERFACE}" up

timeout --foreground --signal=INT --kill-after=5s "${WIRE_TIMEOUT:-1900s}" \
	ip netns exec "${HEADROOM_NAMESPACE}" "${HEADROOM_EXEC_PREFIX[@]}" \
	env "${HEADROOM_CHILD_ENV[@]}" "${HEADROOM_BINARY}" --role headroom \
	--generator-interface "${HEADROOM_SOURCE_INTERFACE}" \
	--generator-mac "${HEADROOM_SOURCE_MAC}" --access-mac "${HEADROOM_SINK_MAC}" "$@"
