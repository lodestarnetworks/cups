#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY="$(cd -- "${SCRIPT_DIR}/../.." && pwd -P)"
NAMESPACE="lodestar-sgwu-service-$$"
BINARY="${SGWU_BINARY:-${REPOSITORY}/bin/sgw-u}"
CONFIG="${SCRIPT_DIR}/sgw-u.tcx-smoke.yaml"
NAMESPACE_CREATED=0

cleanup() {
	set +e
	if [[ "${NAMESPACE_CREATED}" == "1" ]]; then
		ip netns del "${NAMESPACE}" 2>/dev/null
	fi
}
trap cleanup EXIT INT TERM

if (( EUID != 0 )); then
	printf 'Run this isolated service smoke test as root.\n' >&2
	exit 1
fi
for file in "${BINARY}" "${CONFIG}"; do
	if [[ ! -f "${file}" || -L "${file}" ]]; then
		printf 'Required input must be a regular non-symlink file: %s\n' "${file}" >&2
		exit 1
	fi
done
if [[ ! -x "${BINARY}" ]]; then
	printf 'SGW-U binary is not executable: %s\n' "${BINARY}" >&2
	exit 1
fi

ip netns add "${NAMESPACE}"
NAMESPACE_CREATED=1
ip -n "${NAMESPACE}" link set lo up
ip -n "${NAMESPACE}" addr add 10.253.3.1/32 dev lo
ip -n "${NAMESPACE}" link add lstacc type veth peer name lstenb
ip -n "${NAMESPACE}" link add lstcore type veth peer name lstpgw
ip -n "${NAMESPACE}" link set lstacc address 02:00:00:00:a1:01
ip -n "${NAMESPACE}" link set lstenb address 02:00:00:00:a1:02
ip -n "${NAMESPACE}" link set lstcore address 02:00:00:00:a2:01
ip -n "${NAMESPACE}" link set lstpgw address 02:00:00:00:a2:02
ip -n "${NAMESPACE}" addr add 10.253.1.1/24 dev lstacc
ip -n "${NAMESPACE}" addr add 10.253.1.2/24 dev lstenb
ip -n "${NAMESPACE}" addr add 10.253.2.1/24 dev lstcore
ip -n "${NAMESPACE}" addr add 10.253.2.2/24 dev lstpgw
for interface in lstacc lstenb lstcore lstpgw; do
	ip -n "${NAMESPACE}" link set "${interface}" up
done

set +e
timeout --foreground --signal=INT --kill-after=2s 3s \
	ip netns exec "${NAMESPACE}" \
	setpriv --reuid nobody --regid nogroup --clear-groups \
	--bounding-set=-all,+net_admin,+bpf \
	--inh-caps=-all,+net_admin,+bpf \
	--ambient-caps=-all,+net_admin,+bpf --nnp \
	"${BINARY}" --config "${CONFIG}"
STATUS=$?
set -e

if [[ "${STATUS}" != "0" && "${STATUS}" != "124" ]]; then
	printf 'Restricted SGW-U startup failed with status %d.\n' "${STATUS}" >&2
	exit "${STATUS}"
fi
printf 'Restricted SGW-U TCX startup and graceful timeout shutdown passed.\n'
