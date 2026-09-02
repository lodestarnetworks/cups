#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY="$(cd -- "${SCRIPT_DIR}/../.." && pwd -P)"
source "${SCRIPT_DIR}/wire-host-tuning.sh"
WIRE_PARENT_INTERFACE="${WIRE_PARENT_INTERFACE:-}"
WIRE_DUT_NAMESPACE="lodestar-sgwu-wire-dut-$$"
WIRE_ACCESS_INTERFACE="lswacc"
WIRE_CORE_INTERFACE="lswcore"
WIRE_ACCESS_MAC="${WIRE_ACCESS_MAC:-02:4c:53:57:00:01}"
WIRE_CORE_MAC="${WIRE_CORE_MAC:-02:4c:53:57:00:02}"
WIRE_GENERATOR_MAC="${WIRE_GENERATOR_MAC:-02:4c:53:57:00:03}"
WIRE_BINARY="${SGWU_WIRE_BENCH_BINARY:-${REPOSITORY}/bin/sgwu-wire-bench}"
WIRE_CPU_LIST="${BENCH_CPU_LIST:-}"
WIRE_GO_PROCS="${BENCH_GOMAXPROCS:-}"
WIRE_NAMESPACE_CREATED=0

cleanup() {
	set +e
	if [[ "${WIRE_NAMESPACE_CREATED}" == "1" ]]; then
		ip netns del "${WIRE_DUT_NAMESPACE}" 2>/dev/null
	fi
	wire_tuning_end
}
trap cleanup EXIT INT TERM HUP

if (( EUID != 0 )); then
	printf 'Run the physical-wire DUT wrapper as root.\n' >&2
	exit 1
fi
if [[ -z "${WIRE_PARENT_INTERFACE}" ]]; then
	printf 'Set WIRE_PARENT_INTERFACE to the dedicated benchmark parent interface.\n' >&2
	exit 2
fi
if [[ ! -f "${WIRE_BINARY}" || ! -x "${WIRE_BINARY}" || -L "${WIRE_BINARY}" ]]; then
	printf 'Benchmark binary must be an executable regular file, not a symlink: %s\n' "${WIRE_BINARY}" >&2
	exit 1
fi
if ! ip link show dev "${WIRE_PARENT_INTERFACE}" >/dev/null 2>&1; then
	printf 'Parent interface does not exist: %s\n' "${WIRE_PARENT_INTERFACE}" >&2
	exit 1
fi
if ip netns list | awk '{print $1}' | grep -Fxq "${WIRE_DUT_NAMESPACE}"; then
	printf 'Refusing to reuse network namespace %s\n' "${WIRE_DUT_NAMESPACE}" >&2
	exit 1
fi
for wire_mac in "${WIRE_ACCESS_MAC}" "${WIRE_CORE_MAC}" "${WIRE_GENERATOR_MAC}"; do
	if ip -o link | tr '[:upper:]' '[:lower:]' | grep -Fq "link/ether ${wire_mac,,}"; then
		printf 'Benchmark MAC already exists on DUT host: %s\n' "${wire_mac}" >&2
		exit 1
	fi
done

WIRE_EXEC_PREFIX=()
if [[ -n "${WIRE_CPU_LIST}" ]]; then
	if [[ ! "${WIRE_CPU_LIST}" =~ ^[0-9,-]+$ ]]; then
		printf 'Invalid BENCH_CPU_LIST: %s\n' "${WIRE_CPU_LIST}" >&2
		exit 1
	fi
	WIRE_EXEC_PREFIX=(taskset --cpu-list "${WIRE_CPU_LIST}")
fi
WIRE_CHILD_ENV=("SGW_NEXT_SGWU_WIRE_BENCH=1" "BENCH_CPU_LIST=${WIRE_CPU_LIST}")
if [[ -n "${WIRE_GO_PROCS}" ]]; then
	if [[ ! "${WIRE_GO_PROCS}" =~ ^[1-9][0-9]*$ ]]; then
		printf 'Invalid BENCH_GOMAXPROCS: %s\n' "${WIRE_GO_PROCS}" >&2
		exit 1
	fi
	WIRE_CHILD_ENV+=("GOMAXPROCS=${WIRE_GO_PROCS}")
fi

wire_tuning_begin "${WIRE_PARENT_INTERFACE}"

ip netns add "${WIRE_DUT_NAMESPACE}"
WIRE_NAMESPACE_CREATED=1
ip link add link "${WIRE_PARENT_INTERFACE}" name "${WIRE_ACCESS_INTERFACE}" address "${WIRE_ACCESS_MAC}" type macvlan mode bridge
ip link add link "${WIRE_PARENT_INTERFACE}" name "${WIRE_CORE_INTERFACE}" address "${WIRE_CORE_MAC}" type macvlan mode bridge
ip link set "${WIRE_ACCESS_INTERFACE}" netns "${WIRE_DUT_NAMESPACE}"
ip link set "${WIRE_CORE_INTERFACE}" netns "${WIRE_DUT_NAMESPACE}"
ip -n "${WIRE_DUT_NAMESPACE}" link set lo up
ip -n "${WIRE_DUT_NAMESPACE}" address add 198.18.0.1/32 dev "${WIRE_ACCESS_INTERFACE}"
ip -n "${WIRE_DUT_NAMESPACE}" address add 198.18.0.2/32 dev "${WIRE_CORE_INTERFACE}"
ip -n "${WIRE_DUT_NAMESPACE}" link set "${WIRE_ACCESS_INTERFACE}" up
ip -n "${WIRE_DUT_NAMESPACE}" link set "${WIRE_CORE_INTERFACE}" up

printf 'SGW-U wire DUT namespace=%s parent=%s access=%s/%s core=%s/%s generator=%s\n' \
	"${WIRE_DUT_NAMESPACE}" "${WIRE_PARENT_INTERFACE}" \
	"${WIRE_ACCESS_INTERFACE}" "${WIRE_ACCESS_MAC}" \
	"${WIRE_CORE_INTERFACE}" "${WIRE_CORE_MAC}" "${WIRE_GENERATOR_MAC}" >&2

timeout --foreground --signal=INT --kill-after=5s "${WIRE_TIMEOUT:-1900s}" \
	ip netns exec "${WIRE_DUT_NAMESPACE}" "${WIRE_EXEC_PREFIX[@]}" \
	env "${WIRE_CHILD_ENV[@]}" "${WIRE_BINARY}" --role dut \
	--access-interface "${WIRE_ACCESS_INTERFACE}" --core-interface "${WIRE_CORE_INTERFACE}" \
	--access-mac "${WIRE_ACCESS_MAC}" --core-mac "${WIRE_CORE_MAC}" \
	--generator-mac "${WIRE_GENERATOR_MAC}" "$@"
