#!/usr/bin/env bash
set -Eeuo pipefail

script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repository=$(cd -- "${script_directory}/../.." && pwd -P)
binary_directory=${BINARY_DIRECTORY:-${repository}/bin}
namespace_prefix=${CUPS_SERVICE_NAMESPACE:-lodestar-cups-services}
sgw_namespace=${namespace_prefix}-sgw
pgw_namespace=${namespace_prefix}-pgw
state_directory=/run/lodestar-cups-services
evidence_directory=''
cycles=${CYCLES:-3}
throughput_duration=${THROUGHPUT_DURATION:-2s}
target_pps=${TARGET_PPS:-50000}
run_active_crash=${RUN_ACTIVE_CRASH:-1}
active_hold_seconds=${ACTIVE_HOLD_SECONDS:-20}
admission_hold_seconds=${ADMISSION_HOLD_SECONDS:-8}
active_test_pid=''
declare -A component_pid=()
declare -A recovery_ms=([sgw-c]=0 [sgw-u]=0 [pgw-c]=0 [pgw-u]=0)

cleanup() {
  status=$?
  trap - EXIT INT TERM
  set +e
  if [[ -n "$active_test_pid" ]] && kill -0 "$active_test_pid" 2>/dev/null; then
    kill "$active_test_pid" 2>/dev/null
    wait "$active_test_pid" 2>/dev/null
  fi
  for component in sgw-c sgw-u pgw-c pgw-u; do
    pid=${component_pid[$component]:-}
    [[ -n "$pid" ]] || continue
    if kill -0 "$pid" 2>/dev/null; then
      kill -INT "$pid" 2>/dev/null
    fi
  done
  for _ in $(seq 1 50); do
    running=0
    for component in sgw-c sgw-u pgw-c pgw-u; do
      pid=${component_pid[$component]:-}
      if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        running=1
      fi
    done
    ((running == 0)) && break
    sleep 0.1
  done
  for component in sgw-c sgw-u pgw-c pgw-u; do
    pid=${component_pid[$component]:-}
    [[ -n "$pid" ]] || continue
    if kill -0 "$pid" 2>/dev/null; then
      kill -KILL "$pid" 2>/dev/null
    fi
    wait "$pid" 2>/dev/null
  done
  for namespace in "$sgw_namespace" "$pgw_namespace"; do
    if ip netns list | awk '{print $1}' | grep -Fxq "$namespace"; then
      ip netns delete "$namespace"
    fi
  done
  if [[ -d "$state_directory" && ! -L "$state_directory" ]]; then
    rm -r -- "$state_directory"
  fi
  if ((status != 0)) && [[ -n "$evidence_directory" ]]; then
    printf 'Four-component service qualification failed; evidence=%s\n' "$evidence_directory" >&2
    for log in "$evidence_directory"/*.log; do
      [[ -f "$log" ]] || continue
      printf '%s\n' "--- ${log} ---" >&2
      tail -n 80 "$log" >&2
    done
  elif ((status == 0)); then
    printf 'cleanup=pass\n'
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

if ((EUID != 0)); then
  echo 'Run this isolated four-component qualification as root.' >&2
  exit 2
fi
if ! [[ "$cycles" =~ ^[1-9][0-9]*$ ]] || ((cycles > 1000)); then
  echo 'CYCLES must be an integer from 1 through 1000.' >&2
  exit 2
fi
if ! [[ "$target_pps" =~ ^[0-9]+$ ]]; then
  echo 'TARGET_PPS must be a non-negative integer.' >&2
  exit 2
fi
if [[ "$run_active_crash" != 0 && "$run_active_crash" != 1 ]]; then
  echo 'RUN_ACTIVE_CRASH must be 0 or 1.' >&2
  exit 2
fi
if ! [[ "$active_hold_seconds" =~ ^[0-9]+$ ]] ||
  ((active_hold_seconds < 5 || active_hold_seconds > 300)); then
  echo 'ACTIVE_HOLD_SECONDS must be an integer from 5 through 300.' >&2
  exit 2
fi
if ! [[ "$admission_hold_seconds" =~ ^[0-9]+$ ]] ||
  ((admission_hold_seconds < 3 || admission_hold_seconds > 60)); then
  echo 'ADMISSION_HOLD_SECONDS must be an integer from 3 through 60.' >&2
  exit 2
fi
if [[ "$namespace_prefix" != lodestar-cups-services* ]]; then
  echo 'CUPS_SERVICE_NAMESPACE must begin with lodestar-cups-services.' >&2
  exit 2
fi
for command_name in awk chmod curl date grep install ip jq mktemp openssl rm seq sleep sysctl tail touch; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'Required command is missing: %s\n' "$command_name" >&2
    exit 2
  }
done
for component in sgw-c sgw-u pgw-c pgw-u cups-service-e2e; do
  if [[ ! -f "${binary_directory}/${component}" || ! -x "${binary_directory}/${component}" || -L "${binary_directory}/${component}" ]]; then
    printf 'Required binary must be an executable regular file: %s\n' "${binary_directory}/${component}" >&2
    exit 2
  fi
done
for component in sgw-c sgw-u pgw-c pgw-u; do
  config="${script_directory}/cups-services-${component}.yaml"
  if [[ ! -f "$config" || -L "$config" ]]; then
    printf 'Required configuration must be a regular file: %s\n' "$config" >&2
    exit 2
  fi
done
for namespace in "$sgw_namespace" "$pgw_namespace"; do
  if ip netns list | awk '{print $1}' | grep -Fxq "$namespace"; then
    printf 'Refusing to reuse existing namespace %s.\n' "$namespace" >&2
    exit 2
  fi
done
if [[ -e "$state_directory" || -L "$state_directory" ]]; then
  printf 'Refusing to replace existing state path %s.\n' "$state_directory" >&2
  exit 2
fi

evidence_directory=$(mktemp -d /var/tmp/lodestar-cups-services.XXXXXXXX)
install -d -m 0700 "$state_directory"
openssl rand -hex -out "${state_directory}/subscriber-salt" 32
openssl rand -hex -out "${state_directory}/pgw-policy-token" 32
chmod 0600 "${state_directory}/subscriber-salt" "${state_directory}/pgw-policy-token"

ip netns add "$sgw_namespace"
ip netns add "$pgw_namespace"
ip -n "$sgw_namespace" link set lo up
ip -n "$pgw_namespace" link set lo up
for address in 10.253.31.1 10.253.31.2 10.253.60.1 10.253.60.2; do
  ip -n "$sgw_namespace" address add "${address}/32" dev lo
done
for address in 10.253.32.1 10.253.32.2 10.253.40.3 10.253.60.3 10.253.60.4 10.253.70.1 10.253.70.2 10.253.80.2; do
  ip -n "$pgw_namespace" address add "${address}/32" dev lo
done

create_link() {
  sgw_interface=$1
  pgw_interface=$2
  sgw_mac=$3
  pgw_mac=$4
  sgw_address=$5
  pgw_address=$6
  ip -n "$sgw_namespace" link add "$sgw_interface" type veth peer name "$pgw_interface" netns "$pgw_namespace"
  ip -n "$sgw_namespace" link set "$sgw_interface" address "$sgw_mac"
  ip -n "$pgw_namespace" link set "$pgw_interface" address "$pgw_mac"
  ip -n "$sgw_namespace" address add "${sgw_address}/24" dev "$sgw_interface"
  ip -n "$pgw_namespace" address add "${pgw_address}/24" dev "$pgw_interface"
  ip -n "$sgw_namespace" link set "$sgw_interface" up
  ip -n "$pgw_namespace" link set "$pgw_interface" up
}

create_link lcss11 lcsmme 02:00:00:00:c0:01 02:00:00:00:c0:02 10.253.10.1 10.253.10.2
create_link lcss5c lcspgmc 02:00:00:00:c3:01 02:00:00:00:c3:02 10.253.20.1 10.253.20.2
create_link lcsacc lcsenb 02:00:00:00:c1:01 02:00:00:00:c1:02 10.253.40.1 10.253.40.2
create_link lcscore lcspgw 02:00:00:00:c2:01 02:00:00:00:c2:02 10.253.50.1 10.253.50.2
ip -n "$pgw_namespace" address add 10.253.50.3/24 dev lcspgw

for namespace in "$sgw_namespace" "$pgw_namespace"; do
  ip netns exec "$namespace" sysctl -q -w net.ipv4.ip_forward=1
  ip netns exec "$namespace" sysctl -q -w net.ipv4.conf.all.rp_filter=0
  ip netns exec "$namespace" sysctl -q -w net.ipv4.conf.default.rp_filter=0
done
for interface in lcss11 lcss5c lcsacc lcscore; do
  ip netns exec "$sgw_namespace" sysctl -q -w "net.ipv4.conf.${interface}.rp_filter=0"
done
for interface in lcsmme lcspgmc lcsenb lcspgw; do
  ip netns exec "$pgw_namespace" sysctl -q -w "net.ipv4.conf.${interface}.rp_filter=0"
done

for component in sgw-c sgw-u; do
  ip netns exec "$sgw_namespace" "${binary_directory}/${component}" \
    --config "${script_directory}/cups-services-${component}.yaml" --check-config
done
for component in pgw-c pgw-u; do
  ip netns exec "$pgw_namespace" "${binary_directory}/${component}" \
    --config "${script_directory}/cups-services-${component}.yaml" --check-config
done

start_component() {
  component=$1
  case "$component" in
    sgw-c | sgw-u) component_namespace=$sgw_namespace ;;
    pgw-c | pgw-u) component_namespace=$pgw_namespace ;;
    *) printf 'Unknown component %s.\n' "$component" >&2; return 2 ;;
  esac
  printf '%s start %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$component" \
    >>"${evidence_directory}/${component}.log"
  ip netns exec "$component_namespace" "${binary_directory}/${component}" \
    --config "${script_directory}/cups-services-${component}.yaml" \
    >>"${evidence_directory}/${component}.log" 2>&1 &
  component_pid[$component]=$!
}

wait_ready() {
  for _ in $(seq 1 300); do
    if ip netns exec "$sgw_namespace" curl -fsS --max-time 1 \
        -o "${evidence_directory}/sgwc.metrics" http://10.253.60.1:8080/metrics 2>/dev/null &&
      ip netns exec "$sgw_namespace" curl -fsS --max-time 1 \
        -o "${evidence_directory}/sgwu.metrics" http://10.253.60.2:8081/metrics 2>/dev/null &&
      ip netns exec "$pgw_namespace" curl -fsS --max-time 1 \
        -o "${evidence_directory}/pgwc.health" http://10.253.60.3:8180/healthz 2>/dev/null &&
      ip netns exec "$pgw_namespace" curl -fsS --max-time 1 \
        -o "${evidence_directory}/pgwu.health" http://10.253.60.4:8181/healthz 2>/dev/null &&
      grep -Fq 'state="associated"} 1' "${evidence_directory}/sgwc.metrics" &&
      grep -Fq 'state="associated"} 1' "${evidence_directory}/sgwu.metrics" &&
      grep -Fq '"status":"associated"' "${evidence_directory}/pgwc.health" &&
      grep -Fq '"status":"associated"' "${evidence_directory}/pgwu.health"; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

wait_sessions() {
  expected=$1
  for _ in $(seq 1 300); do
    if ip netns exec "$sgw_namespace" curl -fsS --max-time 1 \
        -o "${evidence_directory}/sgw-sessions.metrics" http://10.253.60.1:8080/metrics 2>/dev/null &&
      ip netns exec "$pgw_namespace" curl -fsS --max-time 1 \
        -o "${evidence_directory}/pgwc-sessions.metrics" http://10.253.60.3:8180/metrics 2>/dev/null &&
      ip netns exec "$pgw_namespace" curl -fsS --max-time 1 \
        -o "${evidence_directory}/pgwu-sessions.metrics" http://10.253.60.4:8181/metrics 2>/dev/null &&
      grep -Fxq "sgw_next_sgwc_active_sessions ${expected}" "${evidence_directory}/sgw-sessions.metrics" &&
      grep -Fxq "sgw_next_sgwu_pfcp_sessions ${expected}" "${evidence_directory}/sgw-sessions.metrics" &&
      grep -Fq "pfcp_sessions_active{apn=\"lodestartest\",node=\"pgw-c\"} ${expected}" "${evidence_directory}/pgwc-sessions.metrics" &&
      grep -Fq "pfcp_sessions_active{apn=\"lodestartest\",node=\"pgw-u\"} ${expected}" "${evidence_directory}/pgwu-sessions.metrics"; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

wait_admission_state() {
  component=$1
  expected=$2
  case "$component" in
    sgw-c)
      namespace=$sgw_namespace
      endpoint=http://10.253.60.1:8080/metrics
      metric=sgw_next_sgwc_admission_draining
      ;;
    pgw-c)
      namespace=$pgw_namespace
      endpoint=http://10.253.60.3:8180/metrics
      metric=lodestar_pgw_admission_draining
      ;;
    *)
      printf 'Unknown admission component %s.\n' "$component" >&2
      return 2
      ;;
  esac
  for _ in $(seq 1 300); do
    if ip netns exec "$namespace" curl -fsS --max-time 1 -o "${evidence_directory}/${component}-admission.metrics" "$endpoint" 2>/dev/null &&
      awk -v metric="$metric" -v expected="$expected" '
        index($1, metric) == 1 && $2 == expected { found=1 }
        END { exit(found ? 0 : 1) }
      ' "${evidence_directory}/${component}-admission.metrics"; then
      return 0
    fi
    sleep 0.05
  done
  return 1
}

admission_rejections() {
  component=$1
  case "$component" in
    sgw-c)
      metric=sgw_next_sgwc_create_session_admission_rejections_total
      ;;
    pgw-c)
      metric=lodestar_pgw_create_session_total
      ;;
  esac
  awk -v component="$component" -v metric="$metric" '
    component == "sgw-c" && $1 == metric { print $2; found=1 }
    component == "pgw-c" && index($1, metric) == 1 && $1 ~ /result="admission_drained"/ { print $2; found=1 }
    END { if (!found) print 0 }
  ' "${evidence_directory}/${component}-admission.metrics" | tail -n 1
}

wait_admission_rejection() {
  component=$1
  for _ in $(seq 1 100); do
    wait_admission_state "$component" 1
    if test "$(admission_rejections "$component")" -gt 0; then
      return 0
    fi
    sleep 0.05
  done
  return 1
}

start_component pgw-u
start_component pgw-c
start_component sgw-u
start_component sgw-c
if ! wait_ready; then
  echo 'All four services did not associate before the deadline.' >&2
  exit 1
fi

for component in sgw-c pgw-c; do
  wait_admission_state "$component" 0
  existing_file="${evidence_directory}/admission-existing-${component}.json"
  ip netns exec "$pgw_namespace" "${binary_directory}/cups-service-e2e" \
    --mme 10.253.10.2:2123 --sgw-s11 10.253.10.1:2123 \
    --enodeb-user 10.253.40.2:2152 --external-user 10.253.80.2:40001 \
    --imsi 001010123456789 --apn lodestartest --timeout 5s \
    --hold-after-modify "${admission_hold_seconds}s" --json >"$existing_file" &
  active_test_pid=$!
  wait_sessions 1
  touch "${state_directory}/${component}.drain"
  wait_admission_state "$component" 1
  if ip netns exec "$pgw_namespace" "${binary_directory}/cups-service-e2e" \
      --mme 10.253.10.2:2124 --sgw-s11 10.253.10.1:2123 \
      --enodeb-user 10.253.40.3:2152 --external-user 10.253.80.2:40002 \
      --imsi 001010123456780 --mme-teid 0x7a000002 --enodeb-teid 0x7b000002 \
      --apn lodestartest --timeout 2s \
      >"${evidence_directory}/admission-${component}.log" 2>&1; then
    printf '%s drain unexpectedly admitted a new session.\n' "$component" >&2
    exit 1
  fi
  wait_sessions 1
  wait_admission_rejection "$component"
  wait "$active_test_pid"
  active_test_pid=''
  wait_sessions 0
  rm -- "${state_directory}/${component}.drain"
  wait_admission_state "$component" 0
  jq -e --argjson admissionHoldSeconds "$admission_hold_seconds" \
    '.apn == "lodestartest" and .uplinkPayloadBytes > 0 and
     .downlinkPayloadBytes > 0 and
     .holdAfterModifyMilliseconds >= ($admissionHoldSeconds * 1000)' \
    "$existing_file" >/dev/null
done

cycle_files=()
for cycle in $(seq 1 "$cycles"); do
  cycle_file="${evidence_directory}/cycle-${cycle}.json"
  cycle_files+=("$cycle_file")
  ip netns exec "$pgw_namespace" "${binary_directory}/cups-service-e2e" \
    --mme 10.253.10.2:2123 --sgw-s11 10.253.10.1:2123 \
    --enodeb-user 10.253.40.2:2152 --external-user 10.253.80.2:40001 \
    --imsi 001010123456789 --apn lodestartest --timeout 5s \
    --throughput-duration "$throughput_duration" --target-pps "$target_pps" \
    --json >"$cycle_file"
  jq -e \
    '.apn == "lodestartest" and .ueIpv4 != "" and
     .uplinkPayloadBytes > 0 and .downlinkPayloadBytes > 0 and
     .uplinkThroughput.lossPercent == 0 and .downlinkThroughput.lossPercent == 0' \
    "$cycle_file" >/dev/null
done

if [[ "$run_active_crash" == 1 ]]; then
  for component in sgw-u pgw-u sgw-c pgw-c; do
    active_file="${evidence_directory}/active-crash-${component}.json"
    ip netns exec "$pgw_namespace" "${binary_directory}/cups-service-e2e" \
      --mme 10.253.10.2:2123 --sgw-s11 10.253.10.1:2123 \
      --enodeb-user 10.253.40.2:2152 --external-user 10.253.80.2:40001 \
      --imsi 001010123456789 --apn lodestartest --timeout 5s \
      --hold-after-modify "${active_hold_seconds}s" --json >"$active_file" &
    active_test_pid=$!
    wait_sessions 1

    old_pid=${component_pid[$component]}
    recovery_started=$(date +%s%3N)
    kill -KILL "$old_pid"
    wait "$old_pid" 2>/dev/null || true
    start_component "$component"
    wait_ready
    wait_sessions 1
    recovery_finished=$(date +%s%3N)
    recovery_ms[$component]=$((recovery_finished - recovery_started))

    wait "$active_test_pid"
    active_test_pid=''
    jq -e --argjson activeHoldSeconds "$active_hold_seconds" \
      '.apn == "lodestartest" and .uplinkPayloadBytes > 0 and
       .downlinkPayloadBytes > 0 and
       .holdAfterModifyMilliseconds >= ($activeHoldSeconds * 1000)' \
      "$active_file" >/dev/null
    wait_sessions 0
  done
fi

stores_zero=0
for _ in $(seq 1 100); do
  ip netns exec "$sgw_namespace" curl -fsS -o "${evidence_directory}/sgw-final.metrics" http://10.253.60.1:8080/metrics
  ip netns exec "$pgw_namespace" curl -fsS -o "${evidence_directory}/pgwc-final.metrics" http://10.253.60.3:8180/metrics
  ip netns exec "$pgw_namespace" curl -fsS -o "${evidence_directory}/pgwu-final.metrics" http://10.253.60.4:8181/metrics
  if grep -Fxq 'sgw_next_sgwc_active_sessions 0' "${evidence_directory}/sgw-final.metrics" &&
    grep -Fxq 'sgw_next_sgwu_pfcp_sessions 0' "${evidence_directory}/sgw-final.metrics" &&
    grep -Fq 'pfcp_sessions_active{apn="lodestartest",node="pgw-c"} 0' "${evidence_directory}/pgwc-final.metrics" &&
    grep -Fq 'pfcp_sessions_active{apn="lodestartest",node="pgw-u"} 0' "${evidence_directory}/pgwu-final.metrics"; then
    stores_zero=1
    break
  fi
  sleep 0.1
done
if ((stores_zero != 1)); then
  echo 'Session stores did not converge to zero after detach.' >&2
  exit 1
fi
grep -Fxq 'sgw_next_sgwc_active_sessions 0' "${evidence_directory}/sgw-final.metrics"
grep -Fxq 'sgw_next_sgwu_pfcp_sessions 0' "${evidence_directory}/sgw-final.metrics"
grep -Fq 'pfcp_sessions_active{apn="lodestartest",node="pgw-c"} 0' "${evidence_directory}/pgwc-final.metrics"
grep -Fq 'pfcp_sessions_active{apn="lodestartest",node="pgw-u"} 0' "${evidence_directory}/pgwu-final.metrics"

fast_path_packets=$(awk '$1 == "sgw_next_sgwu_fast_path_forwarded_packets_total" {print $2}' "${evidence_directory}/sgw-final.metrics")
urr_packets=$(awk '$1 == "sgw_next_sgwu_urr_metered_packets_total" {print $2}' "${evidence_directory}/sgw-final.metrics")
sync_failures=$(awk '$1 == "sgw_next_sgwu_fast_path_sync_failures_total" {print $2}' "${evidence_directory}/sgw-final.metrics")
rewrite_errors=$(awk '$1 == "sgw_next_sgwu_fast_path_rewrite_errors_total" {print $2}' "${evidence_directory}/sgw-final.metrics")
context_not_found_reconciliations=$(awk '$1 == "sgw_next_sgwc_delete_session_context_not_found_reconciliations_total" {print $2}' "${evidence_directory}/sgw-final.metrics")
test "${fast_path_packets:-0}" -gt 0
test "${urr_packets:-0}" -gt 0
test "${sync_failures:-0}" -eq 0
test "${rewrite_errors:-0}" -eq 0
if [[ "$run_active_crash" == 1 ]]; then
  test "${context_not_found_reconciliations:-0}" -gt 0
fi

jq -s \
  --argjson fastPathPackets "$fast_path_packets" \
  --argjson urrPackets "$urr_packets" \
  --argjson activeCrash "$run_active_crash" \
  --argjson sgwcRecovery "${recovery_ms[sgw-c]}" \
  --argjson sgwuRecovery "${recovery_ms[sgw-u]}" \
  --argjson pgwcRecovery "${recovery_ms[pgw-c]}" \
  --argjson pgwuRecovery "${recovery_ms[pgw-u]}" \
  --argjson contextNotFoundReconciliations "${context_not_found_reconciliations:-0}" \
  '{status: "pass", cycles: length,
    uplinkMbps: {average: (map(.uplinkThroughput.mbps) | add / length), minimum: (map(.uplinkThroughput.mbps) | min)},
    downlinkMbps: {average: (map(.downlinkThroughput.mbps) | add / length), minimum: (map(.downlinkThroughput.mbps) | min)},
    uplinkLossPercent: (map(.uplinkThroughput.lossPercent) | max),
    downlinkLossPercent: (map(.downlinkThroughput.lossPercent) | max),
    fastPathPackets: $fastPathPackets, urrMeteredPackets: $urrPackets,
    activeSessionCrashRecovery: {enabled: ($activeCrash == 1), milliseconds:
      {sgwC: $sgwcRecovery, sgwU: $sgwuRecovery, pgwC: $pgwcRecovery, pgwU: $pgwuRecovery}},
    idempotentDeleteReconciliations: $contextNotFoundReconciliations,
    admissionDrainGate: {sgwC: true, pgwC: true, existingStatePreserved: true},
    allFourSessionStoresZero: true}' \
  "${cycle_files[@]}" >"${evidence_directory}/summary.json"

jq . "${evidence_directory}/summary.json"
printf 'evidence=%s\n' "$evidence_directory"
