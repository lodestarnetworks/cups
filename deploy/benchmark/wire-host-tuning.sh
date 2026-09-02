#!/usr/bin/env bash

# Sourced by the physical-wire wrappers. Changes are opt-in via WIRE_FORMAL=1
# and every original value is restored by wire_tuning_end.

declare -Ag WIRE_SAVED_GOVERNORS=()
declare -Ag WIRE_SAVED_IRQ_AFFINITIES=()
declare -Ag WIRE_SAVED_OFFLOADS=()
declare -ag WIRE_TUNED_IRQS=()
WIRE_TUNING_ACTIVE=0
WIRE_TUNING_PHYSICAL_INTERFACE=""
WIRE_IRQBALANCE_WAS_ACTIVE=0
WIRE_SAVED_RX_RING=""
WIRE_TUNED_RX_RING=""

wire_resolve_physical_interface() {
	local parent_interface="$1"
	local lower_path
	for lower_path in "/sys/class/net/${parent_interface}"/lower_*; do
		if [[ -e "${lower_path}" ]]; then
			basename "${lower_path}" | sed 's/^lower_//'
			return 0
		fi
	done
	printf '%s\n' "${parent_interface}"
}

wire_offload_state() {
	local interface="$1"
	local feature_name="$2"
	ethtool -k "${interface}" | awk -F: -v wanted="${feature_name}" '
		$1 == wanted {
			gsub(/^[[:space:]]+/, "", $2)
			split($2, fields, /[[:space:]]+/)
			print fields[1]
			exit
		}'
}

wire_ring_value() {
	local interface="$1"
	local section="$2"
	ethtool -g "${interface}" | awk -v wanted="${section}" '
		/^Pre-set maximums:/ { current = "maximum"; next }
		/^Current hardware settings:/ { current = "current"; next }
		current == wanted && $1 == "RX:" { print $2; exit }
	'
}

wire_expand_cpu_list() {
	local cpu_list="$1"
	local item first last cpu
	local -a items=()
	IFS=',' read -r -a items <<<"${cpu_list}"
	for item in "${items[@]}"; do
		if [[ "${item}" == *-* ]]; then
			first="${item%-*}"
			last="${item#*-}"
			for ((cpu = first; cpu <= last; cpu++)); do
				printf '%s\n' "${cpu}"
			done
		else
			printf '%s\n' "${item}"
		fi
	done
}

wire_tuning_begin() {
	local parent_interface="$1"
	if [[ "${WIRE_FORMAL:-0}" != "1" ]]; then
		return 0
	fi
	WIRE_TUNING_ACTIVE=1
	WIRE_TUNING_PHYSICAL_INTERFACE="${WIRE_PHYSICAL_INTERFACE:-$(wire_resolve_physical_interface "${parent_interface}")}"
	if ! ip link show dev "${WIRE_TUNING_PHYSICAL_INTERFACE}" >/dev/null 2>&1; then
		printf 'Unable to resolve physical benchmark interface from %s\n' "${parent_interface}" >&2
		return 1
	fi

	local short_name feature_name original_value feature_index
	local -a short_names=(gro gso tso lro)
	local -a feature_names=(
		generic-receive-offload generic-segmentation-offload
		tcp-segmentation-offload large-receive-offload
	)
	for feature_index in "${!short_names[@]}"; do
		short_name="${short_names[feature_index]}"
		feature_name="${feature_names[feature_index]}"
		original_value="$(wire_offload_state "${WIRE_TUNING_PHYSICAL_INTERFACE}" "${feature_name}")"
		if [[ "${original_value}" != "on" && "${original_value}" != "off" ]]; then
			printf 'Unable to read %s on %s\n' "${feature_name}" "${WIRE_TUNING_PHYSICAL_INTERFACE}" >&2
			return 1
		fi
		WIRE_SAVED_OFFLOADS["${short_name}"]="${original_value}"
	done

	WIRE_SAVED_RX_RING="$(wire_ring_value "${WIRE_TUNING_PHYSICAL_INTERFACE}" current)"
	WIRE_TUNED_RX_RING="$(wire_ring_value "${WIRE_TUNING_PHYSICAL_INTERFACE}" maximum)"
	if [[ "${WIRE_SAVED_RX_RING}" =~ ^[0-9]+$ && "${WIRE_TUNED_RX_RING}" =~ ^[0-9]+$ ]] &&
		(( WIRE_TUNED_RX_RING > WIRE_SAVED_RX_RING )); then
		ethtool -G "${WIRE_TUNING_PHYSICAL_INTERFACE}" rx "${WIRE_TUNED_RX_RING}"
	fi
	for feature_index in "${!short_names[@]}"; do
		short_name="${short_names[feature_index]}"
		feature_name="${feature_names[feature_index]}"
		ethtool -K "${WIRE_TUNING_PHYSICAL_INTERFACE}" "${short_name}" off >/dev/null
		if [[ "$(wire_offload_state "${WIRE_TUNING_PHYSICAL_INTERFACE}" "${feature_name}")" != "off" ]]; then
			printf 'Failed to disable %s on %s\n' "${feature_name}" "${WIRE_TUNING_PHYSICAL_INTERFACE}" >&2
			return 1
		fi
	done

	local governor_path
	for governor_path in /sys/devices/system/cpu/cpufreq/policy*/scaling_governor; do
		[[ -w "${governor_path}" ]] || continue
		WIRE_SAVED_GOVERNORS["${governor_path}"]="$(<"${governor_path}")"
		printf 'performance\n' >"${governor_path}"
		if [[ "$(<"${governor_path}")" != "performance" ]]; then
			printf 'Failed to select performance governor at %s\n' "${governor_path}" >&2
			return 1
		fi
	done

	if systemctl is-active --quiet irqbalance 2>/dev/null; then
		WIRE_IRQBALANCE_WAS_ACTIVE=1
		systemctl stop irqbalance
	fi

	local irq cpu_index=0
	local -a irq_cpus=()
	if [[ -n "${WIRE_IRQ_CPU_LIST:-}" ]]; then
		mapfile -t irq_cpus < <(wire_expand_cpu_list "${WIRE_IRQ_CPU_LIST}")
		if (( ${#irq_cpus[@]} == 0 )); then
			printf 'WIRE_IRQ_CPU_LIST expanded to no CPUs\n' >&2
			return 1
		fi
		while read -r irq; do
			[[ -w "/proc/irq/${irq}/smp_affinity_list" ]] || continue
			WIRE_SAVED_IRQ_AFFINITIES["${irq}"]="$(<"/proc/irq/${irq}/smp_affinity_list")"
			WIRE_TUNED_IRQS+=("${irq}")
			printf '%s\n' "${irq_cpus[cpu_index % ${#irq_cpus[@]}]}" >"/proc/irq/${irq}/smp_affinity_list"
			((cpu_index += 1))
		done < <(awk -v device="${WIRE_TUNING_PHYSICAL_INTERFACE}" '
			$0 ~ device && $NF ~ /(-q[0-9]+|-fp-[0-9]+)$/ {
				gsub(/:/, "", $1)
				print $1
			}' /proc/interrupts)
	fi

	printf 'Formal host tuning active: interface=%s offloads=gro,gso,tso,lro:off rx_ring=%s governors=performance irq_cpus=%s\n' \
		"${WIRE_TUNING_PHYSICAL_INTERFACE}" "${WIRE_TUNED_RX_RING:-unchanged}" "${WIRE_IRQ_CPU_LIST:-unchanged}" >&2
}

wire_tuning_end() {
	if [[ "${WIRE_TUNING_ACTIVE}" != "1" ]]; then
		return 0
	fi
	set +e
	local irq governor_path short_name original_value
	for irq in "${WIRE_TUNED_IRQS[@]}"; do
		printf '%s\n' "${WIRE_SAVED_IRQ_AFFINITIES[${irq}]}" >"/proc/irq/${irq}/smp_affinity_list" 2>/dev/null
	done
	if [[ "${WIRE_IRQBALANCE_WAS_ACTIVE}" == "1" ]]; then
		systemctl start irqbalance 2>/dev/null
	fi
	for governor_path in "${!WIRE_SAVED_GOVERNORS[@]}"; do
		printf '%s\n' "${WIRE_SAVED_GOVERNORS[${governor_path}]}" >"${governor_path}" 2>/dev/null
	done
	for short_name in gro gso tso lro; do
		original_value="${WIRE_SAVED_OFFLOADS[${short_name}]:-}"
		if [[ "${original_value}" == "on" || "${original_value}" == "off" ]]; then
			ethtool -K "${WIRE_TUNING_PHYSICAL_INTERFACE}" "${short_name}" "${original_value}" >/dev/null 2>&1
		fi
	done
	if [[ "${WIRE_SAVED_RX_RING}" =~ ^[0-9]+$ ]]; then
		ethtool -G "${WIRE_TUNING_PHYSICAL_INTERFACE}" rx "${WIRE_SAVED_RX_RING}" >/dev/null 2>&1
	fi
	WIRE_TUNING_ACTIVE=0
}
