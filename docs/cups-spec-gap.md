# Lodestar CUPS specification traceability

This file records implementation status against the Lodestar CUPS specification supplied on 2026-08-30. It intentionally excludes credentials and does not assert regulatory status.

> **Performance evidence warning:** the physical-link zero-loss result is not
> a complete product capacity rating and must not be used alone to size or
> advertise the gateway. Same-host and virtual-host figures remain synthetic
> regression evidence. See `benchmark-methodology.md` and `performance.md`.

## Datapath capability gate

The host probe and isolated forwarding benchmark were run on a development
virtual machine and the target bare-metal host. Loading the signed `gtp`
module created no interface, route, or PDP context, and no subscriber path was
changed.

| Capability | Development VM | Bare-metal target |
|---|---|---|
| Virtualisation | KVM | bare metal |
| Kernel | 6.8.0-138-generic | 6.8.0-134-generic |
| Kernel GTP module | matching `linux-modules-extra` package installed; module loads and the `gtp` generic-netlink family is present | signed module loads and the `gtp` generic-netlink family is present |
| BTF | present | present |
| BPF JIT / XDP / AF_XDP kernel support | available | available |
| NIC | `virtio_net`, one queue | `be2net`, 14 active combined queues, MTU up to 9000 |
| Native XDP attach | not selected because kernel GTP passed the preferred gate | `be2net` exposes no native XDP/offload hook; no program was attached to the live interface |

Decision status: **kernel GTP over generic netlink selected for PGW-U; TCX/eBPF selected for the current SGW-U fast-path slice**. Both passed on the two hosts. The current SGW-U slice handles plain IPv4 G-PDUs and uses the portable Go backend as its explicit fallback. Native XDP remains an optimisation for supported future NICs rather than a prerequisite for this TCX implementation.

The PGW-U controller now creates and owns the GTP device, bound UDP socket,
routes, PDP contexts, and a pre-GTP nftables outer-peer allowlist. Real packet
tests prove authorized encapsulation/decapsulation and unauthorized-source
rejection. PFCP establish/modify/delete programs the live kernel, and isolated
churn passed at 1,000,000 contexts with zero orphans. Clean WAL replay and
abrupt-crash recovery are implemented: a mode-0600 persistent random token
plus an exclusive process lock fences each link, and the same token must be
present on both the GTP interface and complete nftables table before either can
be reclaimed. Real `SIGKILL` recovery and foreign-resource preservation passed
on virtual and bare-metal hosts. The complete SGW-C → PGW-C → PFCP →
kernel-GTP lifecycle has also passed with 100,000 simultaneous sessions, zero
transport errors, and zero leaked state. SGW-C and PGW-C now have local
fsync-before-acknowledgement authority, atomic compaction, exact allocator
restore, and bounded PFCP replay. Directional dedicated-bearer TFTs,
gate/bitrate QERs, volume URR telemetry, a separate QCI 1 kernel path, and
mixed default/QCI 1 physical traffic have passed. Both user planes emit
ordered standards-shaped PFCP usage reports and both control planes durably
reconcile duplicates, gaps, conflicts, restart epochs, and crash tails. PGW-C
also exposes a protected, durable, idempotent policy-controller API for
dedicated bearers. Production remains gated on real UE/VoLTE interoperability,
deployment of an authoritative policy decision service or Gx adapter,
complete SGW-U protocol coverage, full endurance qualification, signed-release
approval, and cross-site replication/fencing.

## Requirement status

| Requirement | Current status | Remaining gate |
|---|---|---|
| R1 APN/location selection | Not implemented | YAML topology, TAI/eNB selectors, association-aware fallback, combined `sae-gw-u` |
| R2 IMS DDN | Implemented in the SGW reference path: standard BAR lifecycle, bounded per-QCI/per-bearer buffering, QCI 5 priority, ARP-bearing DDN, duplicate suppression, and DDN-to-paging-response histograms | Validate live MME/eNodeB paging and QCI 5 behaviour under bulk-data contention |
| R3 no online charging | Compliant by design; per-bearer URR volume is emitted as ordered PFCP usage reports, durably duplicate-safe reconciled by SGW-C/PGW-C, and never gates traffic | Complete the long soak and add an external accounting export/audit only if later operational policy requires it |
| R4 TFT direction | Implemented for the production-safe LTE IPv4 packet-filter subset; wrong-bearer traffic fails closed and physical QCI 1 traffic passed in both directions | Validate against live MME/UE captures and add explicitly gated compatibility handling only if interop requires it |
| R5 PFCP grace/reconcile | Implemented in SGW-U and PGW-U control/rule paths; local durable CP restart replay passed at 10,000 sessions | Run the 60-second backhaul-pull acceptance test on an isolated APN; add cross-site recovery under R12 |
| R6 S8 roaming | Not implemented and off | IPsec-only peer profiles, Serving Network/RAT/ULI validation and metrics |
| R7 addressing/NAT | IPv4 vertical slice in progress | IPv6/IPv4v6, NAT64, deterministic persistent CGNAT blocks |
| R8 MTU/MSS | Partial: PGW-C negotiates a bounded IPv4 link MTU through UE PCO | Per-eNB outer MTU, MSS clamp, IPv6 PTB, fragmentation metrics |
| R9 QCI 1 telemetry | Partial: active bearer, rule, forwarding, QER-drop, URR-volume and external benchmark latency/loss are available | Add bounded live per-eNB jitter/loss aggregation and opt-in subscriber debugging |
| R10 emergency APN | Not implemented | Safe-off gate plus complete enable path and audit metric |
| R11 fast path | PGW-U kernel GTP, portable Go-SGW-U → kernel-PGW-U, and a revision-safe TCX/eBPF SGW-U plain-IPv4 slice are implemented. Corrected physical QCI 1 traffic sustained 8,959.996 Mbps in each direction at zero loss; mixed default/QCI 1 traffic loaded each fibre direction to about 9,090 Mbps at zero loss | Add VLAN/IPv6/extension-header coverage, mixed mobile IMIX, fallback-contention, long small-packet soak, and dynamic-next-hop handling |
| R12 resilience | Local SGW-C/PGW-C durable authority, durable GTP peer Recovery counters, fail-closed four-node stale-session cleanup, atomic compaction, PFCP restart replay, PGW-U WAL reconciliation, and ownership-fenced abrupt-crash kernel recovery are implemented. Three integrated 1,000-session fault runs recovered 2% loss, 1% duplication, 25% reordering, and a mid-run control restart with zero failed procedures or leaks | Authenticated state replication and quorum-backed active/standby fencing across two sites; long backhaul-pull and split-brain drills |
| R13 fair-use shaping | Not implemented and off | Separate optional rolling-window policy; no charging coupling |
| R14 conformance | Defensive codecs and LTE lifecycle tests exist | VectorCore and Go-MME interop suites; named deviation flags |

## Implemented PGW vertical slice

- Defensive GTPv2-C IPv4 PAA and PDN Type codecs.
- Bounded, concurrency-safe IPv4 lease pool.
- Bounded PGW-C and PGW-U session stores with indexed UE-IP and tunnel lookup.
- Sxb PFCP association, heartbeat, session establishment, tunnel modification, deletion, peer ownership checks, and restart detection.
- S5-C Create Session, Modify Bearer, and Delete Session lifecycle for `lodestartest`, with hashed subscriber identity and rollback on partial failure.
- Defensive UE PCO/IPCP negotiation for two IPv4 DNS servers and IPv4 link MTU, relayed unchanged by SGW-C to the MME.
- APN-AMBR policy is configured and stored in bits per second, encoded in GTPv2-C kbps fields, and enforced in PFCP without silently losing sub-kbps precision.
- Default-bearer MBR/GBR values are retained for PFCP replay; the effective QER limit is the lower non-zero value of bearer MBR and APN-AMBR.
- Development-only S5-U/SGi forwarding model with UE-source anti-spoofing and classified drop counters.
- Shared PFCP `associated` → `grace` → `reconciling` state machine with a 120-second default, no-new-session gate, forwarding-state retention, authoritative replay, stale-rule removal, expiry cleanup, and Prometheus state/countdown metrics.
- Atomic SGW replay includes default and dedicated bearer rules in one PFCP transaction so a VoLTE bearer is not partially reconstructed.
- Directional IPv4 TFT classification, separate default/QCI 1 kernel-GTP
  devices, transactional bearer routing, gate/bitrate QER enforcement, and
  telemetry-only per-bearer URR metering are implemented and passed physical
  mixed-traffic validation.
- Ordered Sxa/Sxb PFCP usage-report emission with retry/backoff, bounded queues,
  sequence and restart-epoch handling, fsync-before-acknowledgement control-plane
  ledgers, duplicate-safe replay, gap/conflict detection, and compaction. The
  isolated running-service gate has delivered and durably acknowledged real
  bidirectional packet deltas over both interfaces with zero retry, gap, or
  conflict.
- A protected PGW-C policy API with stable persisted policy IDs, idempotent
  create/update/delete semantics, strict IPv4 TFT/QoS validation, bounded
  concurrency, owner-only token files, and mandatory TLS 1.3 mTLS off loopback.
- Standards-based PFCP BAR create/update/remove, BUFF/NOCP handling, ARP-bearing S11 DDN, duplicate suppression, and bounded downlink queues with independent QCI 5/default limits are implemented in the SGW reference path.
- Successful Modify Bearer responses release buffered packets in order and feed bounded per-QCI/per-eNodeB DDN-to-paging-response histograms; buffer occupancy, releases, expiry, overflow, and purge counters are exported to JSON, Prometheus, and the SGW-only dashboard.
- PGW-U kernel-GTP backend driven directly through rtnetlink and generic netlink, with transactional PFCP-to-PDP mutation and rollback.
- Per-link nftables peer allowlist at the IPv4 input hook, ownership-safe cleanup, and accepted/dropped packet counters exported through the PGW-U metrics model.
- Machine-visible backend capability gauges and startup warnings for every unsupported production feature.
- Locked, checksummed, fsync-backed PGW-U write-ahead log with partial-tail recovery, transactional dataplane rollback, clean-restart kernel reconstruction, and duplicate-safe PFCP replay.
- Locked, checksummed SGW-C/PGW-C authority journals with fsync-before-GTP-ack commits, strict semantic replay, exact UE-lease/TEID/SEID restore, partial-tail recovery, stable local owner fencing, and atomic snapshot compaction.
- Separate locked peer-recovery journals for both control planes, correct
  per-interface Recovery IE stamping, fail-closed downstream deletion, and
  idempotent GTP/PFCP cleanup retries after MME or SGW-C restart detection.
- Bare-metal durable restart evidence: 10,000 complete sessions reconciled in 1,373.646 ms with zero retransmissions, worker/socket drops, stale purges, or leaks; a 16 MiB stress run completed five SGW-C and two PGW-C compactions without losing state.
- Durable scale evidence: 100,000 simultaneous sessions and UE leases survived a complete SGW-C/PGW-C restart and authoritative PFCP replay in 16,330.046 ms, then all were modified/deleted with zero failures or leaked state; the all-in-one harness peaked at about 1.53 GiB RSS.
- Integrated control-fault evidence: a real concurrent-duplicate race was found and fixed with in-flight GTPv2-C/PFCP coalescing. Three subsequent fsync-durable 1,000-session runs combined 2% loss, 1% duplication, 25% reordering, and SGW-C/PGW-C restart/reconciliation; all 9,000 lifecycle procedures succeeded, 2,622 retransmissions and 1,874 duplicate events were recovered, and every run ended with zero timeouts, drops, or leaked state.
- Locked per-link ownership records with 256-bit random identities; restart removes only exact-token GTP and nftables leftovers, refuses concurrent owners, and preserves wrong-token, wrong-interface-type, and unowned-firewall objects.
- Isolated VPS evidence: 982.63 Mbps uplink / 1,395.68 Mbps downlink at 0% measured UDP loss, 0.024 ms idle p95 RTT, and 1,000,000-context churn with zero orphans.
- Isolated bare-metal evidence: 30,514.60 Mbps uplink / 34,007.36 Mbps downlink fixed-packet software-path saturation at 0.00% loss; 1,000,000 contexts created at 21,561/s and deleted at 21,917/s with zero orphans.
- Complete bare-metal user-plane chain evidence: batched SGW-U receive/transmit repeatedly carried at least 2,673.293 Mbps aggregate at 0.00% loss; a measured 1,919.863 Mbps point recorded 5 ms uplink / 0.5 ms downlink p95. An unpaced 18,939.183 Mbps offered load delivered 3,550.881 Mbps but suffered 84.21%/77.61% directional loss and is explicitly classified as overload, not capacity.
- SGW-U-only bare-metal TCX evidence: three unpaced hard-saturation repeats delivered 24,861.744–25,179.270 Mbps aggregate with zero sender/receiver loss, capture drops, BPF drops, fallback, sync failures, or rewrite errors. External p95 was 10 ms and sampled eBPF-handler p95 was 0.002 ms. This did not include kernel PGW-U or a physical NIC.
- Complete TCX SGW-U → kernel-GTP PGW-U evidence: three bidirectional 650,000-packet/s-per-direction runs delivered at least 12,432.806 Mbps aggregate at zero loss, with at most 5 ms external p95 and 0.001 ms sampled SGW-U handler p95. Every load packet was counted by both gateways with zero fallback or gateway error. At 675,000 packets/s per direction the same-host synthetic receiver became non-repeatably lossy while both gateways still forwarded every offered packet.
- Complete bare-metal control-plane evidence: 100,000 simultaneous SGW-C/PGW-C/SGW-U/PGW-U/IPAM sessions created at 7,647.75/s with 14.11 ms p95, then modified and deleted with zero retransmissions, worker drops, control-socket drops, kernel errors, or leaked state.
- Strict PGW-U durability evidence: the final instrumented 10,000-session run sustained 2,550 fsync-before-acknowledgement creates/s with 41.79 ms p95 and exactly 20,000 checksummed WAL transitions; earlier repeats reached 2,648.93–3,219.58/s.
- Physical-wire qualification: the active 10,000 Mbps `be2net` path carried the corrected dedicated-bearer and mixed profiles without gateway, NIC, or softnet drops at the accepted rates. UDP RSS still hashes only source and destination IP, so one fixed GTP-U peer pair cannot spread by TEID and remains a scaling constraint.
- Strict YAML configuration and `--check-config` on all four processes; shipped component addressing is restricted to `10.0.0.0/8`.

## Immediate implementation order

1. Add authenticated SGW-C/PGW-C state replication and quorum-backed active/standby fencing across two independent sites.
2. Deploy and interoperate an authoritative policy-decision service or Gx/PCRF adapter against the protected PGW-C API; soak and audit the implemented PFCP usage-report path.
3. Extend the implemented plain-IPv4 TCX path with VLAN, IPv6, extension-header, fragment, MTU, and dynamic-next-hop handling while keeping BAR-backed buffering on the explicit portable fallback.
4. Extend the passed mixed default/QCI 1 physical profile with mobile IMIX, small-packet stress, fallback contention, and a multi-day voice-latency soak. Current component and full-chain baselines are recorded under `benchmarks/`.
5. Implement APN/location user-plane selection and combined edge-pod mode.
6. Add IPv6/NAT64/deterministic CGNAT, MTU controls, and IMS-specific telemetry.
7. Canary data for one UE on `lodestartest`, then validate live dedicated-bearer/VoLTE interop before expanding subscriber scope; continue fuzz, fault, long-soak, and failover gates in parallel.
