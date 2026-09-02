#!/usr/bin/env bash
set -euo pipefail

namespace="lodestar-sgw-bench"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd -- "${script_dir}/../.." && pwd)"
binary_dir="${project_dir}/bin"
run_dir=""
sgwc_pid=""
sgwu_pid=""
tune_host_sockets=false
host_tuned=false
original_rmem_max=""
original_wmem_max=""
original_backlog=""
original_udp_rmem_min=""
original_udp_wmem_min=""

if [[ ${1:-} == "--tune-host-sockets" ]]; then
  tune_host_sockets=true
  shift
fi

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  for process_id in "${sgwc_pid}" "${sgwu_pid}"; do
    if [[ -n "${process_id}" ]] && kill -0 "${process_id}" 2>/dev/null; then
      kill "${process_id}" 2>/dev/null || true
      wait "${process_id}" 2>/dev/null || true
    fi
  done
  if ip netns list | awk '{print $1}' | grep -Fxq "${namespace}"; then
    ip netns delete "${namespace}"
  fi
  if [[ ${host_tuned} == true ]]; then
    sysctl -q -w "net.core.rmem_max=${original_rmem_max}" || true
    sysctl -q -w "net.core.wmem_max=${original_wmem_max}" || true
    sysctl -q -w "net.core.netdev_max_backlog=${original_backlog}" || true
    sysctl -q -w "net.ipv4.udp_rmem_min=${original_udp_rmem_min}" || true
    sysctl -q -w "net.ipv4.udp_wmem_min=${original_udp_wmem_min}" || true
  fi
  if [[ ${status} -ne 0 && -n "${run_dir}" ]]; then
    printf 'Benchmark failed. Component logs are in %s\n' "${run_dir}" >&2
  fi
  exit "${status}"
}
trap cleanup EXIT INT TERM

if [[ ${EUID} -ne 0 ]]; then
  printf 'Run this isolated network-namespace benchmark as root.\n' >&2
  exit 1
fi
for command_name in ip curl awk grep mktemp seq sleep sysctl; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    printf 'Required command is missing: %s\n' "${command_name}" >&2
    exit 1
  fi
done
for binary_name in sgw-c sgw-u sgw-e2e; do
  if [[ ! -x "${binary_dir}/${binary_name}" ]]; then
    printf 'Missing %s; run make build first.\n' "${binary_dir}/${binary_name}" >&2
    exit 1
  fi
done
if ip netns list | awk '{print $1}' | grep -Fxq "${namespace}"; then
  printf 'Refusing to replace an existing namespace named %s.\n' "${namespace}" >&2
  exit 1
fi

run_dir="$(mktemp -d /tmp/lodestar-sgw-bench.XXXXXX)"
if [[ ${tune_host_sockets} == true ]]; then
  original_rmem_max="$(sysctl -n net.core.rmem_max)"
  original_wmem_max="$(sysctl -n net.core.wmem_max)"
  original_backlog="$(sysctl -n net.core.netdev_max_backlog)"
  original_udp_rmem_min="$(sysctl -n net.ipv4.udp_rmem_min)"
  original_udp_wmem_min="$(sysctl -n net.ipv4.udp_wmem_min)"
  host_tuned=true
  sysctl -q -w net.core.rmem_max=16777216
  sysctl -q -w net.core.wmem_max=16777216
  sysctl -q -w net.core.netdev_max_backlog=250000
  sysctl -q -w net.ipv4.udp_rmem_min=262144
  sysctl -q -w net.ipv4.udp_wmem_min=262144
fi
ip netns add "${namespace}"
ip -n "${namespace}" link set lo up
for address in \
  10.254.10.1 10.254.10.2 \
  10.254.20.1 10.254.20.2 \
  10.254.30.1 10.254.30.2 \
  10.254.40.1 10.254.40.2 \
  10.254.50.1 10.254.50.2 \
  10.254.60.1 10.254.60.2; do
  ip -n "${namespace}" address add "${address}/32" dev lo
done

ip netns exec "${namespace}" \
  "${binary_dir}/sgw-u" --config "${script_dir}/sgw-u.vps-netns.yaml" \
  >"${run_dir}/sgw-u.log" 2>&1 &
sgwu_pid=$!

for _ in $(seq 1 100); do
  if ip netns exec "${namespace}" curl --fail --silent --max-time 1 \
    http://10.254.60.2:18081/healthz >/dev/null; then
    break
  fi
  sleep 0.05
done
if ! ip netns exec "${namespace}" curl --fail --silent --max-time 1 \
  http://10.254.60.2:18081/healthz >/dev/null; then
  printf 'SGW-U did not become healthy.\n' >&2
  exit 1
fi

ip netns exec "${namespace}" \
  "${binary_dir}/sgw-c" --config "${script_dir}/sgw-c.vps-netns.yaml" \
  >"${run_dir}/sgw-c.log" 2>&1 &
sgwc_pid=$!

for _ in $(seq 1 100); do
  if ip netns exec "${namespace}" curl --fail --silent --max-time 1 \
    http://10.254.60.1:18080/healthz >/dev/null; then
    break
  fi
  sleep 0.05
done
if ! ip netns exec "${namespace}" curl --fail --silent --max-time 1 \
  http://10.254.60.1:18080/healthz >/dev/null; then
  printf 'SGW-C did not become healthy.\n' >&2
  exit 1
fi

printf 'Running isolated SGW benchmark; rates are reported in Mbps and latency in ms.\n'
ip netns exec "${namespace}" "${binary_dir}/sgw-e2e" "$@"
printf 'Component logs: %s\n' "${run_dir}"
