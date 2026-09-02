#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY="$(cd -- "${SCRIPT_DIR}/../.." && pwd -P)"
source "${SCRIPT_DIR}/wire-host-tuning.sh"
WIRE_PARENT_INTERFACE="${WIRE_PARENT_INTERFACE:-}"
WIRE_DUT_NAMESPACE="lodestar-cups-wire-dut-$$"
WIRE_ACCESS_INTERFACE="lswacc"
WIRE_CORE_INTERFACE="lswcore"
WIRE_PGWU_INTERFACE="lswpgw"
WIRE_SGI_INTERFACE="lswsgi"
WIRE_ACCESS_MAC="${WIRE_ACCESS_MAC:-02:4c:53:57:00:01}"
WIRE_CORE_MAC="${WIRE_CORE_MAC:-02:4c:53:57:00:02}"
WIRE_GENERATOR_MAC="${WIRE_GENERATOR_MAC:-02:4c:53:57:00:03}"
WIRE_PGWU_MAC="${WIRE_PGWU_MAC:-02:4c:53:57:00:04}"
WIRE_SGI_MAC="${WIRE_SGI_MAC:-02:4c:53:57:00:05}"
WIRE_BINARY="${SGWU_WIRE_BENCH_BINARY:-${REPOSITORY}/bin/sgwu-wire-bench}"
WIRE_CPU_LIST="${BENCH_CPU_LIST:-}"
WIRE_GO_PROCS="${BENCH_GOMAXPROCS:-}"
WIRE_ORIGINAL_RMEM="$(sysctl -n net.core.rmem_max)"
WIRE_ORIGINAL_WMEM="$(sysctl -n net.core.wmem_max)"
WIRE_ORIGINAL_BACKLOG="$(sysctl -n net.core.netdev_max_backlog)"
WIRE_NAMESPACE_CREATED=0
WIRE_SOCKET_TUNED=0

cleanup() {
	set +e
	if [[ "${WIRE_NAMESPACE_CREATED}" == "1" ]]; then
		ip netns del "${WIRE_DUT_NAMESPACE}" 2>/dev/null
	fi
	if [[ "${WIRE_SOCKET_TUNED}" == "1" ]]; then
		sysctl -q -w "net.core.rmem_max=${WIRE_ORIGINAL_RMEM}" 2>/dev/null
		sysctl -q -w "net.core.wmem_max=${WIRE_ORIGINAL_WMEM}" 2>/dev/null
		sysctl -q -w "net.core.netdev_max_backlog=${WIRE_ORIGINAL_BACKLOG}" 2>/dev/null
	fi
	wire_tuning_end
}
trap cleanup EXIT INT TERM HUP

if (( EUID != 0 )); then
	printf 'Run the combined CUPS physical-wire DUT wrapper as root.\n' >&2
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
for wire_mac in "${WIRE_ACCESS_MAC}" "${WIRE_CORE_MAC}" "${WIRE_GENERATOR_MAC}" "${WIRE_PGWU_MAC}" "${WIRE_SGI_MAC}"; do
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

if (( WIRE_ORIGINAL_RMEM < 134217728 )); then
	sysctl -q -w net.core.rmem_max=134217728
	WIRE_SOCKET_TUNED=1
fi
if (( WIRE_ORIGINAL_WMEM < 134217728 )); then
	sysctl -q -w net.core.wmem_max=134217728
	WIRE_SOCKET_TUNED=1
fi
# The SGW-U -> kernel-GTP veth handoff can fan a physical receive burst into
# one softnet queue. Match the shipped production floor so that the benchmark
# measures gateway capacity rather than the host's small distribution default.
if (( WIRE_ORIGINAL_BACKLOG < 250000 )); then
	sysctl -q -w net.core.netdev_max_backlog=250000
	WIRE_SOCKET_TUNED=1
fi

wire_tuning_begin "${WIRE_PARENT_INTERFACE}"

ip netns add "${WIRE_DUT_NAMESPACE}"
WIRE_NAMESPACE_CREATED=1
ip link add link "${WIRE_PARENT_INTERFACE}" name "${WIRE_ACCESS_INTERFACE}" address "${WIRE_ACCESS_MAC}" type macvlan mode bridge
ip link add link "${WIRE_PARENT_INTERFACE}" name "${WIRE_SGI_INTERFACE}" address "${WIRE_SGI_MAC}" type macvlan mode bridge
ip link add "${WIRE_CORE_INTERFACE}" type veth peer name "${WIRE_PGWU_INTERFACE}"
ip link set "${WIRE_CORE_INTERFACE}" address "${WIRE_CORE_MAC}"
ip link set "${WIRE_PGWU_INTERFACE}" address "${WIRE_PGWU_MAC}"
for wire_interface in "${WIRE_ACCESS_INTERFACE}" "${WIRE_CORE_INTERFACE}" "${WIRE_PGWU_INTERFACE}" "${WIRE_SGI_INTERFACE}"; do
	ip link set "${wire_interface}" netns "${WIRE_DUT_NAMESPACE}"
done

ip -n "${WIRE_DUT_NAMESPACE}" link set lo up
ip -n "${WIRE_DUT_NAMESPACE}" address add 10.253.166.1/32 dev "${WIRE_ACCESS_INTERFACE}"
ip -n "${WIRE_DUT_NAMESPACE}" address add 10.253.168.1/32 dev "${WIRE_CORE_INTERFACE}"
ip -n "${WIRE_DUT_NAMESPACE}" address add 10.253.168.2/32 dev "${WIRE_PGWU_INTERFACE}"
ip -n "${WIRE_DUT_NAMESPACE}" address add 10.253.168.3/32 dev "${WIRE_PGWU_INTERFACE}"
ip -n "${WIRE_DUT_NAMESPACE}" address add 10.253.169.1/32 dev "${WIRE_SGI_INTERFACE}"
for wire_interface in "${WIRE_ACCESS_INTERFACE}" "${WIRE_CORE_INTERFACE}" "${WIRE_PGWU_INTERFACE}" "${WIRE_SGI_INTERFACE}"; do
	ip -n "${WIRE_DUT_NAMESPACE}" link set "${wire_interface}" up
done

# Force PGW-U downlink GTP-U through the veth into the SGW-U TCX ingress hook
# instead of allowing Linux to short-circuit the SGW-U address over loopback.
ip -n "${WIRE_DUT_NAMESPACE}" route del table local local 10.253.168.1 dev "${WIRE_CORE_INTERFACE}"
ip -n "${WIRE_DUT_NAMESPACE}" route add 10.253.168.1/32 dev "${WIRE_PGWU_INTERFACE}" src 10.253.168.2
ip -n "${WIRE_DUT_NAMESPACE}" neigh add 10.253.168.1 lladdr "${WIRE_CORE_MAC}" nud permanent dev "${WIRE_PGWU_INTERFACE}"

# Uplink packets decapsulated by PGW-U leave over the physical SGi macvlan.
ip -n "${WIRE_DUT_NAMESPACE}" route add 10.253.169.2/32 dev "${WIRE_SGI_INTERFACE}" src 10.253.169.1
ip -n "${WIRE_DUT_NAMESPACE}" neigh add 10.253.169.2 lladdr "${WIRE_GENERATOR_MAC}" nud permanent dev "${WIRE_SGI_INTERFACE}"

ip netns exec "${WIRE_DUT_NAMESPACE}" sysctl -q -w net.ipv4.ip_forward=1
ip netns exec "${WIRE_DUT_NAMESPACE}" sysctl -q -w net.ipv4.ip_nonlocal_bind=1
ip netns exec "${WIRE_DUT_NAMESPACE}" sysctl -q -w net.ipv4.conf.all.rp_filter=0
ip netns exec "${WIRE_DUT_NAMESPACE}" sysctl -q -w net.ipv4.conf.default.rp_filter=0
# The SGW-U and PGW-U veth endpoints intentionally share this disposable
# namespace. Permit the rewritten SGW-U source, whose address is assigned to
# the peer endpoint, to enter the PGW-U kernel-GTP socket.
ip netns exec "${WIRE_DUT_NAMESPACE}" sysctl -q -w "net.ipv4.conf.${WIRE_PGWU_INTERFACE}.accept_local=1"
for wire_interface in "${WIRE_ACCESS_INTERFACE}" "${WIRE_CORE_INTERFACE}" "${WIRE_PGWU_INTERFACE}" "${WIRE_SGI_INTERFACE}"; do
	ip netns exec "${WIRE_DUT_NAMESPACE}" sysctl -q -w "net.ipv4.conf.${wire_interface}.rp_filter=0"
done

if [[ "${WIRE_FORMAL:-0}" == "1" ]]; then
	for wire_interface in "${WIRE_CORE_INTERFACE}" "${WIRE_PGWU_INTERFACE}"; do
		for wire_feature in gro gso tso lro; do
			ip netns exec "${WIRE_DUT_NAMESPACE}" ethtool -K "${wire_interface}" "${wire_feature}" off >/dev/null 2>&1 || true
		done
		if ip netns exec "${WIRE_DUT_NAMESPACE}" ethtool -k "${wire_interface}" |
			grep -Eq '^(generic-receive-offload|generic-segmentation-offload|tcp-segmentation-offload|large-receive-offload): on'; then
			printf 'Failed to disable internal veth offloads on %s\n' "${wire_interface}" >&2
			exit 1
		fi
	done
fi

printf 'CUPS wire DUT namespace=%s parent=%s access=%s/%s S5=%s/%s<->%s/%s SGi=%s/%s generator=%s\n' \
	"${WIRE_DUT_NAMESPACE}" "${WIRE_PARENT_INTERFACE}" \
	"${WIRE_ACCESS_INTERFACE}" "${WIRE_ACCESS_MAC}" \
	"${WIRE_CORE_INTERFACE}" "${WIRE_CORE_MAC}" \
	"${WIRE_PGWU_INTERFACE}" "${WIRE_PGWU_MAC}" \
	"${WIRE_SGI_INTERFACE}" "${WIRE_SGI_MAC}" "${WIRE_GENERATOR_MAC}" >&2

timeout --foreground --signal=INT --kill-after=5s "${WIRE_TIMEOUT:-1900s}" \
	ip netns exec "${WIRE_DUT_NAMESPACE}" "${WIRE_EXEC_PREFIX[@]}" \
	env "${WIRE_CHILD_ENV[@]}" "${WIRE_BINARY}" --role dut --cups-chain \
	--access-interface "${WIRE_ACCESS_INTERFACE}" --core-interface "${WIRE_CORE_INTERFACE}" \
	--pgwu-interface "${WIRE_PGWU_INTERFACE}" --sgi-interface "${WIRE_SGI_INTERFACE}" \
	--access-mac "${WIRE_ACCESS_MAC}" --core-mac "${WIRE_CORE_MAC}" \
	--pgwu-mac "${WIRE_PGWU_MAC}" --sgi-mac "${WIRE_SGI_MAC}" \
	--generator-mac "${WIRE_GENERATOR_MAC}" "$@"
