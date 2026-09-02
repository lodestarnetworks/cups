#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY="$(cd -- "${SCRIPT_DIR}/../.." && pwd -P)"
NAMESPACE="lodestar-kernel-policy-$$"
NAMESPACE_CREATED=0
GO_BINARY="${GO_BINARY:-go}"

cleanup() {
	set +e
	if [[ "${NAMESPACE_CREATED}" == "1" ]]; then
		ip netns del "${NAMESPACE}" 2>/dev/null
	fi
}
trap cleanup EXIT INT TERM HUP

if (( EUID != 0 )); then
	printf 'Run the isolated kernel-policy test as root.\n' >&2
	exit 1
fi
if ip netns list | awk '{print $1}' | grep -Fxq "${NAMESPACE}"; then
	printf 'Refusing to reuse network namespace %s\n' "${NAMESPACE}" >&2
	exit 1
fi

ip netns add "${NAMESPACE}"
NAMESPACE_CREATED=1
ip -n "${NAMESPACE}" link set lo up
ip netns exec "${NAMESPACE}" sysctl -q -w net.ipv4.conf.all.rp_filter=0
ip netns exec "${NAMESPACE}" sysctl -q -w net.ipv4.conf.default.rp_filter=0
for address in 10.254.77.1 10.254.77.2 10.254.77.3 10.254.77.4; do
	ip -n "${NAMESPACE}" address add "${address}/32" dev lo
done

cd "${REPOSITORY}"
timeout --foreground --signal=INT --kill-after=3s 90s \
	ip netns exec "${NAMESPACE}" env SGW_NEXT_KERNEL_GTP_TEST=1 \
	"${GO_BINARY}" test -count=1 -run '^TestKernelGTPPolicyRoutingIntegration$' ./internal/kernelgtp
timeout --foreground --signal=INT --kill-after=3s 90s \
	ip netns exec "${NAMESPACE}" env SGW_NEXT_KERNEL_GTP_TEST=1 \
	"${GO_BINARY}" test -count=1 -run '^TestKernelPolicyDedicatedBearerIntegration$' ./internal/pgwu/dataplane
timeout --foreground --signal=INT --kill-after=3s 90s \
	ip netns exec "${NAMESPACE}" env SGW_NEXT_KERNEL_GTP_TEST=1 \
	"${GO_BINARY}" test -count=1 -run '^TestKernelPolicyDedicatedBearerChurnIntegration$' -v ./internal/pgwu/dataplane
timeout --foreground --signal=INT --kill-after=3s 90s \
	ip netns exec "${NAMESPACE}" env SGW_NEXT_KERNEL_GTP_TEST=1 \
	"${GO_BINARY}" test -count=1 -run '^TestKernelPolicyAbruptRestartRestoresDedicatedBearer$' ./internal/pgwu/dataplane
timeout --foreground --signal=INT --kill-after=3s 90s \
	ip netns exec "${NAMESPACE}" env SGW_NEXT_KERNEL_GTP_TEST=1 \
	"${GO_BINARY}" test -count=1 -run '^TestFullStackKernelDedicatedBearerIntegration$' ./internal/pgwc/gateway
