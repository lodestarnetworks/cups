//go:build ignore

// The SGW-U TCX dataplane intentionally uses a small self-contained UAPI
// surface. Normal builds embed the generated objects and do not need clang or
// kernel headers on the gateway host.

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

struct __sk_buff;

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, value) int (*name)[value]
#define __type(name, value) value *name
#define __always_inline inline __attribute__((always_inline))

#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_PERCPU_ARRAY 6

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

#define ETH_P_IP 0x0800
#define IPPROTO_UDP 17
#define GTPU_PORT 2152
#define GTPU_FLAGS_PLAIN 0x30
#define GTPU_MESSAGE_GPDU 255

#define BPF_F_INVALIDATE_HASH (1ULL << 1)
#define BPF_F_PSEUDO_HDR (1ULL << 4)
#define BPF_F_MARK_MANGLED_0 (1ULL << 5)

#define SIDE_ACCESS 0
#define SIDE_CORE 1
#define SIDE_FLAG_TEST_MODE 1
#define MAX_URRS_PER_RULE 4

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_htons(value) __builtin_bswap16(value)
#define bpf_ntohs(value) __builtin_bswap16(value)
#define bpf_htonl(value) __builtin_bswap32(value)
#define bpf_ntohl(value) __builtin_bswap32(value)
#else
#define bpf_htons(value) (value)
#define bpf_ntohs(value) (value)
#define bpf_htonl(value) (value)
#define bpf_ntohl(value) (value)
#endif

static void *(*bpf_map_lookup_elem)(const void *map, const void *key) = (void *)1;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static long (*bpf_skb_store_bytes)(struct __sk_buff *skb, __u32 offset,
	const void *from, __u32 length, __u64 flags) = (void *)9;
static long (*bpf_l3_csum_replace)(struct __sk_buff *skb, __u32 offset,
	__u64 from, __u64 to, __u64 size) = (void *)10;
static long (*bpf_l4_csum_replace)(struct __sk_buff *skb, __u32 offset,
	__u64 from, __u64 to, __u64 flags) = (void *)11;
static long (*bpf_redirect)(__u32 ifindex, __u64 flags) = (void *)23;
static long (*bpf_skb_load_bytes)(const struct __sk_buff *skb, __u32 offset,
	void *to, __u32 length) = (void *)26;

struct ethernet_header {
	__u8 destination[6];
	__u8 source[6];
	__u16 protocol;
} __attribute__((packed));

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

struct udp_header {
	__u16 source;
	__u16 destination;
	__u16 length;
	__u16 checksum;
} __attribute__((packed));

struct gtpu_header {
	__u8 flags;
	__u8 message_type;
	__u16 length;
	__u32 teid;
} __attribute__((packed));

struct side_configuration {
	__u32 local_ip;
	__u32 flags;
};

struct peer_key {
	__u32 source;
	__u32 ip;
};

struct tunnel_key {
	__u32 source;
	__u32 teid;
};

struct rule_key {
	__u64 up_seid;
	__u64 revision;
	__u32 source;
	__u32 teid;
};

struct rule_value {
	__u32 egress_ifindex;
	__u32 source_ip;
	__u32 destination_ip;
	__u32 teid;
	__u8 source_mac[6];
	__u8 destination_mac[6];
	__u32 urr_count;
	__u32 urr_ids[MAX_URRS_PER_RULE];
	__u32 reserved;
};

struct usage_key {
	__u64 up_seid;
	__u32 urr_id;
	__u32 reserved;
};

struct usage_value {
	__u64 uplink_packets;
	__u64 downlink_packets;
	__u64 uplink_bytes;
	__u64 downlink_bytes;
};

enum counter_index {
	COUNTER_ACCESS_PACKETS,
	COUNTER_CORE_PACKETS,
	COUNTER_FORWARDED_PACKETS,
	COUNTER_FORWARDED_BYTES,
	COUNTER_UPLINK_BYTES,
	COUNTER_DOWNLINK_BYTES,
	COUNTER_UNAUTHORIZED,
	COUNTER_REWRITE_ERRORS,
	COUNTER_FALLBACK_PACKETS,
	COUNTER_MAX,
};

enum latency_bucket_index {
	LATENCY_LE_1_US,
	LATENCY_LE_2_US,
	LATENCY_LE_5_US,
	LATENCY_LE_10_US,
	LATENCY_LE_20_US,
	LATENCY_LE_50_US,
	LATENCY_LE_100_US,
	LATENCY_LE_250_US,
	LATENCY_LE_500_US,
	LATENCY_LE_1_MS,
	LATENCY_LE_2_MS,
	LATENCY_LE_5_MS,
	LATENCY_OVER_5_MS,
	LATENCY_BUCKET_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, struct side_configuration);
} side_configurations SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, struct peer_key);
	__type(value, __u8);
} allowed_peers SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, struct tunnel_key);
	__type(value, __u64);
} tunnel_sessions SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u64);
	__type(value, __u64);
} active_revisions SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2);
	__type(key, struct rule_key);
	__type(value, struct rule_value);
} packet_rules SEC(".maps");

// Usage entries are created by userspace before the corresponding revision is
// activated. A normal hash map keeps memory proportional to active URRs rather
// than active URRs multiplied by the host CPU count; atomic additions preserve
// correctness when RSS sends one bearer through several CPUs.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, struct usage_key);
	__type(value, struct usage_value);
} usage_counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, COUNTER_MAX);
	__type(key, __u32);
	__type(value, __u64);
} counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, LATENCY_BUCKET_MAX);
	__type(key, __u32);
	__type(value, __u64);
} latency_buckets SEC(".maps");

static __always_inline void add_counter(__u32 index, __u64 value)
{
	__u64 *counter = bpf_map_lookup_elem(&counters, &index);
	if (counter)
		*counter += value;
}

static __always_inline int fallback(void)
{
	add_counter(COUNTER_FALLBACK_PACKETS, 1);
	return TC_ACT_OK;
}

static __always_inline void count_consumed(__u32 source)
{
	if (source == SIDE_ACCESS)
		add_counter(COUNTER_ACCESS_PACKETS, 1);
	else
		add_counter(COUNTER_CORE_PACKETS, 1);
}

static __always_inline __u64 sampled_start_time(void)
{
	__u32 index = COUNTER_FORWARDED_PACKETS;
	__u64 *counter = bpf_map_lookup_elem(&counters, &index);
	if (counter && ((*counter & 1023) == 0))
		return bpf_ktime_get_ns();
	return 0;
}

static __always_inline void record_latency(__u64 started)
{
	__u64 elapsed;
	__u32 bucket;
	__u64 *value;
	if (started == 0)
		return;
	elapsed = bpf_ktime_get_ns() - started;
	if (elapsed <= 1000)
		bucket = LATENCY_LE_1_US;
	else if (elapsed <= 2000)
		bucket = LATENCY_LE_2_US;
	else if (elapsed <= 5000)
		bucket = LATENCY_LE_5_US;
	else if (elapsed <= 10000)
		bucket = LATENCY_LE_10_US;
	else if (elapsed <= 20000)
		bucket = LATENCY_LE_20_US;
	else if (elapsed <= 50000)
		bucket = LATENCY_LE_50_US;
	else if (elapsed <= 100000)
		bucket = LATENCY_LE_100_US;
	else if (elapsed <= 250000)
		bucket = LATENCY_LE_250_US;
	else if (elapsed <= 500000)
		bucket = LATENCY_LE_500_US;
	else if (elapsed <= 1000000)
		bucket = LATENCY_LE_1_MS;
	else if (elapsed <= 2000000)
		bucket = LATENCY_LE_2_MS;
	else if (elapsed <= 5000000)
		bucket = LATENCY_LE_5_MS;
	else
		bucket = LATENCY_OVER_5_MS;
	value = bpf_map_lookup_elem(&latency_buckets, &bucket);
	if (value)
		*value += 1;
}

static __always_inline void record_usage(const struct rule_key *rule_key,
	const struct rule_value *rule, __u32 source, __u64 bytes)
{
	struct usage_key key = {};
	struct usage_value *value;
	__u32 index;

	key.up_seid = rule_key->up_seid;
#pragma unroll
	for (index = 0; index < MAX_URRS_PER_RULE; index++) {
		if (index >= rule->urr_count)
			break;
		key.urr_id = rule->urr_ids[index];
		value = bpf_map_lookup_elem(&usage_counters, &key);
		// Session activation is ordered after usage-map population. A miss
		// therefore indicates an externally corrupted map; forwarding remains
		// available while userspace surfaces a synchronization failure.
		if (!value)
			continue;
		if (source == SIDE_ACCESS) {
			__sync_fetch_and_add(&value->uplink_packets, 1);
			__sync_fetch_and_add(&value->uplink_bytes, bytes);
		} else {
			__sync_fetch_and_add(&value->downlink_packets, 1);
			__sync_fetch_and_add(&value->downlink_bytes, bytes);
		}
	}
}

static __always_inline int rewrite_and_redirect(struct __sk_buff *skb,
	const struct ipv4_header *ip, const struct udp_header *udp,
	const struct gtpu_header *gtp, const struct rule_value *rule,
	const struct rule_key *rule_key, const struct side_configuration *side,
	__u32 source)
{
	const __u32 ip_checksum_offset = 14 + 10;
	const __u32 ip_source_offset = 14 + 12;
	const __u32 ip_destination_offset = 14 + 16;
	const __u32 udp_source_offset = 14 + 20;
	const __u32 udp_checksum_offset = 14 + 20 + 6;
	const __u32 gtpu_teid_offset = 14 + 20 + 8 + 4;
	const __u16 gtpu_port = bpf_htons(GTPU_PORT);
	const __u32 new_teid = bpf_htonl(rule->teid);
	const __u64 started = sampled_start_time();

	if (bpf_l3_csum_replace(skb, ip_checksum_offset, ip->source,
			rule->source_ip, 4) < 0 ||
		bpf_l3_csum_replace(skb, ip_checksum_offset, ip->destination,
			rule->destination_ip, 4) < 0)
		goto rewrite_error;

	if (udp->checksum != 0) {
		const __u64 pseudo_flags = 4 | BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0;
		if (bpf_l4_csum_replace(skb, udp_checksum_offset, ip->source,
				rule->source_ip, pseudo_flags) < 0 ||
			bpf_l4_csum_replace(skb, udp_checksum_offset, ip->destination,
				rule->destination_ip, pseudo_flags) < 0 ||
			bpf_l4_csum_replace(skb, udp_checksum_offset, udp->source,
				gtpu_port, 2 | BPF_F_MARK_MANGLED_0) < 0 ||
			bpf_l4_csum_replace(skb, udp_checksum_offset, gtp->teid,
				new_teid, 4 | BPF_F_MARK_MANGLED_0) < 0)
			goto rewrite_error;
	}

	if (bpf_skb_store_bytes(skb, 0, rule->destination_mac, 6, 0) < 0 ||
		bpf_skb_store_bytes(skb, 6, rule->source_mac, 6, 0) < 0 ||
		bpf_skb_store_bytes(skb, ip_source_offset, &rule->source_ip, 4, 0) < 0 ||
		bpf_skb_store_bytes(skb, ip_destination_offset, &rule->destination_ip, 4, 0) < 0 ||
		bpf_skb_store_bytes(skb, udp_source_offset, &gtpu_port, 2, 0) < 0 ||
		bpf_skb_store_bytes(skb, gtpu_teid_offset, &new_teid, 4,
			BPF_F_INVALIDATE_HASH) < 0)
		goto rewrite_error;

	count_consumed(source);
	record_latency(started);
	add_counter(COUNTER_FORWARDED_PACKETS, 1);
	add_counter(COUNTER_FORWARDED_BYTES, bpf_ntohs(gtp->length));
	record_usage(rule_key, rule, source, bpf_ntohs(gtp->length));
	if (source == SIDE_ACCESS)
		add_counter(COUNTER_UPLINK_BYTES, bpf_ntohs(gtp->length));
	else
		add_counter(COUNTER_DOWNLINK_BYTES, bpf_ntohs(gtp->length));
	if (side->flags & SIDE_FLAG_TEST_MODE)
		return TC_ACT_OK;
	return bpf_redirect(rule->egress_ifindex, 0);

rewrite_error:
	count_consumed(source);
	add_counter(COUNTER_REWRITE_ERRORS, 1);
	return TC_ACT_SHOT;
}

static __always_inline int process_packet(struct __sk_buff *skb, __u32 source)
{
	struct ethernet_header ethernet;
	struct ipv4_header ip;
	struct udp_header udp;
	struct gtpu_header gtp;
	struct peer_key peer;
	struct tunnel_key tunnel;
	struct rule_key key;
	struct side_configuration *side;
	struct rule_value *rule;
	__u64 *up_seid;
	__u64 *revision;
	__u8 *allowed;
	__u8 last_byte;
	__u32 ip_length;
	__u32 udp_length;
	__u32 gtp_length;

	side = bpf_map_lookup_elem(&side_configurations, &source);
	if (!side)
		return TC_ACT_OK;
	if (bpf_skb_load_bytes(skb, 0, &ethernet, sizeof(ethernet)) < 0 ||
		ethernet.protocol != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;
	if (bpf_skb_load_bytes(skb, 14, &ip, sizeof(ip)) < 0 ||
		ip.version_ihl != 0x45 || ip.protocol != IPPROTO_UDP ||
		(ip.fragment_offset & bpf_htons(0x3fff)) != 0 ||
		ip.destination != side->local_ip)
		return TC_ACT_OK;
	if (bpf_skb_load_bytes(skb, 14 + 20, &udp, sizeof(udp)) < 0 ||
		udp.destination != bpf_htons(GTPU_PORT))
		return TC_ACT_OK;
	if (bpf_skb_load_bytes(skb, 14 + 20 + 8, &gtp, sizeof(gtp)) < 0 ||
		gtp.flags != GTPU_FLAGS_PLAIN || gtp.message_type != GTPU_MESSAGE_GPDU)
		return TC_ACT_OK;

	ip_length = bpf_ntohs(ip.total_length);
	udp_length = bpf_ntohs(udp.length);
	gtp_length = bpf_ntohs(gtp.length);
	if (udp_length < 16 || gtp_length + 16 != udp_length ||
		ip_length != 20 + udp_length ||
		bpf_skb_load_bytes(skb, 14 + ip_length - 1,
			&last_byte, sizeof(last_byte)) < 0)
		return fallback();

	peer.source = source;
	peer.ip = ip.source;
	allowed = bpf_map_lookup_elem(&allowed_peers, &peer);
	if (!allowed) {
		count_consumed(source);
		add_counter(COUNTER_UNAUTHORIZED, 1);
		return TC_ACT_SHOT;
	}

	tunnel.source = source;
	tunnel.teid = bpf_ntohl(gtp.teid);
	up_seid = bpf_map_lookup_elem(&tunnel_sessions, &tunnel);
	if (!up_seid)
		return fallback();
	revision = bpf_map_lookup_elem(&active_revisions, up_seid);
	if (!revision)
		return fallback();
	key.up_seid = *up_seid;
	key.revision = *revision;
	key.source = source;
	key.teid = tunnel.teid;
	rule = bpf_map_lookup_elem(&packet_rules, &key);
	if (!rule)
		return fallback();
	return rewrite_and_redirect(skb, &ip, &udp, &gtp, rule, &key, side, source);
}

SEC("tcx/ingress")
int sgwu_access_ingress(struct __sk_buff *skb)
{
	return process_packet(skb, SIDE_ACCESS);
}

SEC("tcx/ingress")
int sgwu_core_ingress(struct __sk_buff *skb)
{
	return process_packet(skb, SIDE_CORE);
}

char __license[] SEC("license") = "Dual MIT/GPL";
