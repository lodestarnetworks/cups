//go:build ignore

// The PGW-U kernel-GTP policy layer runs on the inner IPv4 packets exposed by
// the GTP netdevices. Normal builds embed the generated objects and require
// neither clang nor kernel headers on a gateway host.

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

struct __sk_buff;
struct bpf_spin_lock { __u32 val; };

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, value) int (*name)[value]
#define __type(name, value) value *name
#define __always_inline inline __attribute__((always_inline))

#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_PERCPU_HASH 5
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_MAP_TYPE_LRU_HASH 9

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_SCTP 132

#define DIRECTION_UPLINK 0
#define DIRECTION_DOWNLINK 1
#define BEARER_DEFAULT 0
#define BEARER_QCI1 1
#define MAX_TFT_FILTERS 64
#define NANOSECONDS_PER_SECOND 1000000000ULL
#define FRAGMENT_DECISION_TTL_NS (30ULL * NANOSECONDS_PER_SECOND)

#define BPF_ANY 0

#define FILTER_LOCAL_ADDRESS (1U << 0)
#define FILTER_REMOTE_ADDRESS (1U << 1)
#define FILTER_PROTOCOL (1U << 2)
#define FILTER_LOCAL_PORT (1U << 3)
#define FILTER_REMOTE_PORT (1U << 4)
#define FILTER_TOS (1U << 5)

#define GATE_DEFAULT_UPLINK (1U << 0)
#define GATE_DEFAULT_DOWNLINK (1U << 1)
#define GATE_QCI1_UPLINK (1U << 2)
#define GATE_QCI1_DOWNLINK (1U << 3)

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_htons(value) __builtin_bswap16(value)
#define bpf_ntohs(value) __builtin_bswap16(value)
#else
#define bpf_htons(value) (value)
#define bpf_ntohs(value) (value)
#endif

static void *(*bpf_map_lookup_elem)(const void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(const void *map, const void *key,
	const void *value, __u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(const void *map, const void *key) = (void *)3;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static long (*bpf_skb_load_bytes)(const struct __sk_buff *skb, __u32 offset,
	void *to, __u32 length) = (void *)26;
static long (*bpf_spin_lock)(struct bpf_spin_lock *lock) = (void *)93;
static long (*bpf_spin_unlock)(struct bpf_spin_lock *lock) = (void *)94;

struct ipv4_header {
	__u8 version_ihl;
	__u8 tos;
	__u16 total_length;
	__u16 identification;
	__u16 fragment_offset;
	__u8 ttl;
	__u8 protocol;
	__u16 checksum;
	__u32 source;
	__u32 destination;
} __attribute__((packed));

struct transport_ports {
	__u16 source;
	__u16 destination;
} __attribute__((packed));

struct policy_value {
	__u64 up_seid;
	__u64 revision;
	__u64 burst_ns;
	__u64 rates[4];
	__u64 capacities[4];
	__u32 qer_ids[2];
	__u32 urr_ids[2];
	__u16 uplink_filter_count;
	__u16 downlink_filter_count;
	__u8 gate_flags;
	__u8 has_qci1;
	__u16 reserved;
};

struct filter_key {
	__u32 ue_ip;
	__u16 index;
	__u8 direction;
	__u8 reserved;
};

struct filter_value {
	__u32 local_address;
	__u32 local_mask;
	__u32 remote_address;
	__u32 remote_mask;
	__u16 local_port_low;
	__u16 local_port_high;
	__u16 remote_port_low;
	__u16 remote_port_high;
	__u32 precedence;
	__u16 pdr_id;
	__u8 protocol;
	__u8 tos;
	__u8 tos_mask;
	__u8 flags;
	__u16 reserved;
};

struct rate_key {
	__u32 ue_ip;
	__u8 bearer;
	__u8 direction;
	__u16 reserved;
};

struct rate_value {
	struct bpf_spin_lock lock;
	__u32 reserved;
	__u64 revision;
	__u64 qer_id;
	__u64 rate;
	__u64 capacity;
	__u64 tokens;
	__u64 last_ns;
};

struct usage_key {
	__u64 up_seid;
	__u64 revision;
	__u32 qer_id;
	__u32 urr_id;
};

struct usage_value {
	__u64 uplink_packets;
	__u64 uplink_bytes;
	__u64 downlink_packets;
	__u64 downlink_bytes;
};

struct fragment_key {
	__u32 ue_ip;
	__u32 remote_ip;
	__u16 identification;
	__u8 protocol;
	__u8 direction;
};

struct fragment_value {
	__u64 revision;
	__u64 last_ns;
	__u8 bearer;
	__u8 reserved[7];
};

enum counter_index {
	COUNTER_DEFAULT_UPLINK_PACKETS,
	COUNTER_DEFAULT_UPLINK_BYTES,
	COUNTER_DEFAULT_DOWNLINK_PACKETS,
	COUNTER_DEFAULT_DOWNLINK_BYTES,
	COUNTER_QCI1_UPLINK_PACKETS,
	COUNTER_QCI1_UPLINK_BYTES,
	COUNTER_QCI1_DOWNLINK_PACKETS,
	COUNTER_QCI1_DOWNLINK_BYTES,
	COUNTER_QCI1_ROUTE_PACKETS,
	COUNTER_GATE_DROPS,
	COUNTER_RATE_DROPS,
	COUNTER_TFT_WRONG_BEARER_DROPS,
	COUNTER_TFT_UNMATCHED_DROPS,
	COUNTER_MISSING_POLICY_DROPS,
	COUNTER_STALE_POLICY_DROPS,
	COUNTER_MISSING_RATE_DROPS,
	COUNTER_POLICY_MAP_ERRORS,
	COUNTER_MALFORMED_PACKETS,
	COUNTER_FRAGMENT_DROPS,
	COUNTER_USAGE_PACKETS,
	COUNTER_USAGE_BYTES,
	COUNTER_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct policy_value);
} policies SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, struct filter_key);
	__type(value, struct filter_value);
} tft_filters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u64);
	__type(value, __u64);
} active_revisions SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, struct rate_key);
	__type(value, struct rate_value);
} rate_states SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 1);
	__type(key, struct usage_key);
	__type(value, struct usage_value);
} usage_counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1);
	__type(key, struct fragment_key);
	__type(value, struct fragment_value);
} fragment_decisions SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, COUNTER_MAX);
	__type(key, __u32);
	__type(value, __u64);
} counters SEC(".maps");

static __always_inline void add_counter(__u32 index, __u64 value)
{
	__u64 *counter = bpf_map_lookup_elem(&counters, &index);
	if (counter)
		*counter += value;
}

static __always_inline int masked_equal(__u32 packet, __u32 expected, __u32 mask)
{
	return (packet & mask) == (expected & mask);
}

static __always_inline int filter_matches(struct __sk_buff *skb,
	const struct ipv4_header *ip, __u32 header_length, __u8 direction,
	const struct filter_value *filter)
{
	struct transport_ports ports;
	__u32 local_address = direction == DIRECTION_UPLINK ? ip->source : ip->destination;
	__u32 remote_address = direction == DIRECTION_UPLINK ? ip->destination : ip->source;
	__u16 local_port;
	__u16 remote_port;

	if ((filter->flags & FILTER_LOCAL_ADDRESS) &&
		!masked_equal(local_address, filter->local_address, filter->local_mask))
		return 0;
	if ((filter->flags & FILTER_REMOTE_ADDRESS) &&
		!masked_equal(remote_address, filter->remote_address, filter->remote_mask))
		return 0;
	if ((filter->flags & FILTER_PROTOCOL) && ip->protocol != filter->protocol)
		return 0;
	if ((filter->flags & FILTER_TOS) &&
		(ip->tos & filter->tos_mask) != (filter->tos & filter->tos_mask))
		return 0;
	if (!(filter->flags & (FILTER_LOCAL_PORT | FILTER_REMOTE_PORT)))
		return 1;
	if ((ip->fragment_offset & bpf_htons(0x1fff)) != 0 ||
		(ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP && ip->protocol != IPPROTO_SCTP))
		return 0;
	if (bpf_skb_load_bytes(skb, header_length, &ports, sizeof(ports)) < 0)
		return 0;
	local_port = bpf_ntohs(direction == DIRECTION_UPLINK ? ports.source : ports.destination);
	remote_port = bpf_ntohs(direction == DIRECTION_UPLINK ? ports.destination : ports.source);
	if ((filter->flags & FILTER_LOCAL_PORT) &&
		(local_port < filter->local_port_low || local_port > filter->local_port_high))
		return 0;
	if ((filter->flags & FILTER_REMOTE_PORT) &&
		(remote_port < filter->remote_port_low || remote_port > filter->remote_port_high))
		return 0;
	return 1;
}

// Returns 1 for a TFT match, 0 for no match, and -1 when a staged map entry is
// missing. Filters are inserted in precedence order by userspace.
static __always_inline int classify(struct __sk_buff *skb,
	const struct ipv4_header *ip, __u32 header_length, __u32 ue_ip,
	__u8 direction, __u16 count)
{
	struct filter_key key = { .ue_ip = ue_ip, .direction = direction };
	__u32 index;

	for (index = 0; index < MAX_TFT_FILTERS; index++) {
		struct filter_value *filter;
		if (index >= count)
			break;
		key.index = (__u16)index;
		filter = bpf_map_lookup_elem(&tft_filters, &key);
		if (!filter)
			return -1;
		if (filter_matches(skb, ip, header_length, direction, filter))
			return 1;
	}
	return 0;
}

static __always_inline int gate_open(const struct policy_value *policy,
	__u8 bearer, __u8 direction)
{
	__u8 flag;
	if (bearer == BEARER_QCI1)
		flag = direction == DIRECTION_UPLINK ? GATE_QCI1_UPLINK : GATE_QCI1_DOWNLINK;
	else
		flag = direction == DIRECTION_UPLINK ? GATE_DEFAULT_UPLINK : GATE_DEFAULT_DOWNLINK;
	return (policy->gate_flags & flag) != 0;
}

static __always_inline __u32 policy_qer_id(const struct policy_value *policy,
	__u8 bearer)
{
	return bearer == BEARER_QCI1 ? policy->qer_ids[1] : policy->qer_ids[0];
}

static __always_inline __u32 policy_urr_id(const struct policy_value *policy,
	__u8 bearer)
{
	return bearer == BEARER_QCI1 ? policy->urr_ids[1] : policy->urr_ids[0];
}

static __always_inline int enforce_rate(__u32 ue_ip,
	const struct policy_value *policy, __u8 bearer, __u8 direction,
	__u32 packet_bytes)
{
	__u64 rate;
	__u64 capacity;
	__u32 qer_id = policy_qer_id(policy, bearer);
	__u64 packet_bits = (__u64)packet_bytes * 8;
	struct rate_key key = { .ue_ip = ue_ip, .bearer = bearer, .direction = direction };
	struct rate_value *state;
	__u64 now;
	int allowed = 0;

	if (bearer == BEARER_QCI1) {
		if (direction == DIRECTION_UPLINK) {
			rate = policy->rates[2];
			capacity = policy->capacities[2];
		} else {
			rate = policy->rates[3];
			capacity = policy->capacities[3];
		}
	} else if (direction == DIRECTION_UPLINK) {
		rate = policy->rates[0];
		capacity = policy->capacities[0];
	} else {
		rate = policy->rates[1];
		capacity = policy->capacities[1];
	}

	if (rate == 0)
		return 1;
	state = bpf_map_lookup_elem(&rate_states, &key);
	if (!state) {
		add_counter(COUNTER_MISSING_RATE_DROPS, 1);
		return 0;
	}
	now = bpf_ktime_get_ns();
	bpf_spin_lock(&state->lock);
	if (state->revision == policy->revision &&
		state->qer_id == qer_id &&
		state->rate == rate && state->capacity == capacity) {
		if (state->last_ns == 0 || now - state->last_ns >= policy->burst_ns) {
			state->tokens = capacity;
			state->last_ns = now;
		} else if (now > state->last_ns) {
			__u64 elapsed = now - state->last_ns;
			__u64 added = (rate / NANOSECONDS_PER_SECOND) * elapsed;
			added += ((rate % NANOSECONDS_PER_SECOND) * elapsed) / NANOSECONDS_PER_SECOND;
			if (added >= capacity - state->tokens)
				state->tokens = capacity;
			else
				state->tokens += added;
			state->last_ns = now;
		}
		if (state->tokens >= packet_bits) {
			state->tokens -= packet_bits;
			allowed = 1;
		}
	}
	bpf_spin_unlock(&state->lock);
	if (!allowed)
		add_counter(COUNTER_RATE_DROPS, 1);
	return allowed;
}

static __always_inline void record_usage(const struct policy_value *policy,
	__u8 bearer, __u8 direction, __u32 packet_bytes)
{
	struct usage_key key = {
		.up_seid = policy->up_seid,
		// URR volume is cumulative across ordinary PFCP policy revisions. The
		// userspace transaction removes this key on session deletion or when
		// the QER/URR identity changes.
		.revision = 0,
		.qer_id = policy_qer_id(policy, bearer),
		.urr_id = policy_urr_id(policy, bearer),
	};
	struct usage_value *usage;
	if (key.urr_id == 0)
		return;
	usage = bpf_map_lookup_elem(&usage_counters, &key);
	if (!usage) {
		add_counter(COUNTER_POLICY_MAP_ERRORS, 1);
		return;
	}
	if (direction == DIRECTION_UPLINK) {
		usage->uplink_packets++;
		usage->uplink_bytes += packet_bytes;
	} else {
		usage->downlink_packets++;
		usage->downlink_bytes += packet_bytes;
	}
	add_counter(COUNTER_USAGE_PACKETS, 1);
	add_counter(COUNTER_USAGE_BYTES, packet_bytes);
}

static __always_inline int process_packet(struct __sk_buff *skb, __u8 direction,
	__u8 ingress_bearer)
{
	struct ipv4_header ip;
	struct policy_value *policy;
	__u64 *active_revision;
	__u32 header_length;
	__u32 total_length;
	__u32 ue_ip;
	__u8 bearer = BEARER_DEFAULT;
	__u16 filter_count;
	__u16 fragment_bits;
	__u16 fragment_offset;
	__u8 more_fragments;
	__u8 first_fragment = 0;
	__u8 last_byte;
	struct fragment_key fragment_key = {};
	int matched;

	if (bpf_skb_load_bytes(skb, 0, &ip, sizeof(ip)) < 0 || ip.version_ihl >> 4 != 4) {
		add_counter(COUNTER_MALFORMED_PACKETS, 1);
		return TC_ACT_SHOT;
	}
	header_length = (__u32)(ip.version_ihl & 0x0f) * 4;
	total_length = bpf_ntohs(ip.total_length);
	if (header_length < 20 || header_length > 60 || total_length < header_length ||
		bpf_skb_load_bytes(skb, total_length - 1, &last_byte, sizeof(last_byte)) < 0) {
		add_counter(COUNTER_MALFORMED_PACKETS, 1);
		return TC_ACT_SHOT;
	}
	ue_ip = direction == DIRECTION_UPLINK ? ip.source : ip.destination;
	policy = bpf_map_lookup_elem(&policies, &ue_ip);
	if (!policy) {
		add_counter(COUNTER_MISSING_POLICY_DROPS, 1);
		return TC_ACT_SHOT;
	}
	active_revision = bpf_map_lookup_elem(&active_revisions, &policy->up_seid);
	if (!active_revision || *active_revision != policy->revision) {
		add_counter(COUNTER_STALE_POLICY_DROPS, 1);
		return TC_ACT_SHOT;
	}
	fragment_bits = bpf_ntohs(ip.fragment_offset);
	if ((fragment_bits & 0x8000) != 0 ||
		((fragment_bits & 0x4000) != 0 && (fragment_bits & 0x3fff) != 0)) {
		add_counter(COUNTER_MALFORMED_PACKETS, 1);
		return TC_ACT_SHOT;
	}
	fragment_offset = fragment_bits & 0x1fff;
	more_fragments = (fragment_bits & 0x2000) != 0;
	if (fragment_offset != 0) {
		struct fragment_value *decision;
		__u64 now = bpf_ktime_get_ns();
		fragment_key.ue_ip = ue_ip;
		fragment_key.remote_ip = direction == DIRECTION_UPLINK ? ip.destination : ip.source;
		fragment_key.identification = ip.identification;
		fragment_key.protocol = ip.protocol;
		fragment_key.direction = direction;
		decision = bpf_map_lookup_elem(&fragment_decisions, &fragment_key);
		if (!decision || decision->revision != policy->revision ||
			now < decision->last_ns || now - decision->last_ns > FRAGMENT_DECISION_TTL_NS) {
			if (decision)
				bpf_map_delete_elem(&fragment_decisions, &fragment_key);
			add_counter(COUNTER_FRAGMENT_DROPS, 1);
			return TC_ACT_SHOT;
		}
		if (decision->bearer > BEARER_QCI1) {
			bpf_map_delete_elem(&fragment_decisions, &fragment_key);
			add_counter(COUNTER_POLICY_MAP_ERRORS, 1);
			add_counter(COUNTER_FRAGMENT_DROPS, 1);
			return TC_ACT_SHOT;
		}
		bearer = decision->bearer;
		decision->last_ns = now;
		if (!more_fragments && bpf_map_delete_elem(&fragment_decisions, &fragment_key) < 0)
			add_counter(COUNTER_POLICY_MAP_ERRORS, 1);
		if (bearer != ingress_bearer) {
			add_counter(COUNTER_TFT_WRONG_BEARER_DROPS, 1);
			return TC_ACT_SHOT;
		}
	} else {
		filter_count = direction == DIRECTION_UPLINK ? policy->uplink_filter_count : policy->downlink_filter_count;
		matched = classify(skb, &ip, header_length, ue_ip, direction, filter_count);
		if (matched < 0) {
			add_counter(COUNTER_POLICY_MAP_ERRORS, 1);
			return TC_ACT_SHOT;
		}

		if (direction == DIRECTION_UPLINK) {
			if (ingress_bearer == BEARER_QCI1) {
				if (!policy->has_qci1 || !matched) {
					add_counter(COUNTER_TFT_UNMATCHED_DROPS, 1);
					return TC_ACT_SHOT;
				}
				bearer = BEARER_QCI1;
			} else if (matched) {
				add_counter(COUNTER_TFT_WRONG_BEARER_DROPS, 1);
				return TC_ACT_SHOT;
			}
		} else {
			if (policy->has_qci1 && matched)
				bearer = BEARER_QCI1;
			if (bearer != ingress_bearer) {
				if (ingress_bearer == BEARER_QCI1)
					add_counter(COUNTER_TFT_UNMATCHED_DROPS, 1);
				else
					add_counter(COUNTER_TFT_WRONG_BEARER_DROPS, 1);
				return TC_ACT_SHOT;
			}
		}
		if (more_fragments) {
			first_fragment = 1;
			fragment_key.ue_ip = ue_ip;
			fragment_key.remote_ip = direction == DIRECTION_UPLINK ? ip.destination : ip.source;
			fragment_key.identification = ip.identification;
			fragment_key.protocol = ip.protocol;
			fragment_key.direction = direction;
		}
	}

	// Reassert the post-merge range for the verifier and fail closed if a
	// corrupted fragment decision ever escapes the earlier validation.
	if (bearer > BEARER_QCI1) {
		add_counter(COUNTER_POLICY_MAP_ERRORS, 1);
		return TC_ACT_SHOT;
	}
	bearer &= BEARER_QCI1;
	if (!gate_open(policy, bearer, direction)) {
		add_counter(COUNTER_GATE_DROPS, 1);
		return TC_ACT_SHOT;
	}
	if (!enforce_rate(ue_ip, policy, bearer, direction, total_length))
		return TC_ACT_SHOT;
	if (first_fragment) {
		struct fragment_value decision = {
			.revision = policy->revision,
			.last_ns = bpf_ktime_get_ns(),
			.bearer = bearer,
		};
		if (bpf_map_update_elem(&fragment_decisions, &fragment_key, &decision, BPF_ANY) < 0) {
			add_counter(COUNTER_POLICY_MAP_ERRORS, 1);
			add_counter(COUNTER_FRAGMENT_DROPS, 1);
			return TC_ACT_SHOT;
		}
	}
	record_usage(policy, bearer, direction, total_length);

	if (bearer == BEARER_QCI1) {
		if (direction == DIRECTION_UPLINK) {
			add_counter(COUNTER_QCI1_UPLINK_PACKETS, 1);
			add_counter(COUNTER_QCI1_UPLINK_BYTES, total_length);
			return TC_ACT_OK;
		}
		add_counter(COUNTER_QCI1_DOWNLINK_PACKETS, 1);
		add_counter(COUNTER_QCI1_DOWNLINK_BYTES, total_length);
		add_counter(COUNTER_QCI1_ROUTE_PACKETS, 1);
		return TC_ACT_OK;
	}
	if (direction == DIRECTION_UPLINK) {
		add_counter(COUNTER_DEFAULT_UPLINK_PACKETS, 1);
		add_counter(COUNTER_DEFAULT_UPLINK_BYTES, total_length);
	} else {
		add_counter(COUNTER_DEFAULT_DOWNLINK_PACKETS, 1);
		add_counter(COUNTER_DEFAULT_DOWNLINK_BYTES, total_length);
	}
	return TC_ACT_OK;
}

SEC("tcx/ingress")
int pgwu_default_ingress(struct __sk_buff *skb)
{
	return process_packet(skb, DIRECTION_UPLINK, BEARER_DEFAULT);
}

SEC("tcx/egress")
int pgwu_default_egress(struct __sk_buff *skb)
{
	return process_packet(skb, DIRECTION_DOWNLINK, BEARER_DEFAULT);
}

SEC("tcx/ingress")
int pgwu_qci1_ingress(struct __sk_buff *skb)
{
	return process_packet(skb, DIRECTION_UPLINK, BEARER_QCI1);
}

SEC("tcx/egress")
int pgwu_qci1_egress(struct __sk_buff *skb)
{
	return process_packet(skb, DIRECTION_DOWNLINK, BEARER_QCI1);
}

char __license[] SEC("license") = "Dual MIT/GPL";
