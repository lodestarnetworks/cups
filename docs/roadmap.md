# LTE-only roadmap

Each milestone is gated by executable tests. Feature count alone does not make a
gateway production-ready.

## M0 — foundation

Status: complete for the local foundation baseline.

- Go module and local build tooling.
- GTPv2-C, PFCP, and GTP-U header primitives.
- SGW-C session/bearer store with revision checks.
- SGW-U PDR/FAR/QER/URR graph validation.
- Local JSON and Prometheus telemetry.
- SGW-C/SGW-U web dashboard with deterministic lab data.
- Unit tests, fuzz entry points, linting, and type checking.

Exit gate: clean build and tests on a normal unprivileged developer account.

## M1 — protocol engines

- UDP transport with bounded workers and per-peer rate limits.
- Transaction manager with T3/N3 retransmission, response cache, and collision
  policy.
- Full unknown/version/length error handling.
- GTPv2-C and PFCP IE registry with grouped-IE depth and size limits.
- Echo, recovery counters, PFCP heartbeat, association setup/update/release.
- PCAP golden tests and differential decoding against independent libraries.

Exit gate: malformed and fuzzed traffic cannot panic, deadlock, or grow memory
without bounds.

## M2 — default bearer path

- S11 Create Session, Modify Bearer, Delete Session.
- S5/S8-C request forwarding and response correlation.
- PFCP Session Establishment/Modification/Deletion.
- PDR/FAR installation for S1-U and S5/S8-U.
- Portable Go GTP-U forwarder with TEID rewrite and counters.
- End-to-end network-namespace attach and detach test.

Exit gate: an emulated MME/eNB and PGW can attach, exchange bidirectional user
traffic, idle, resume, and detach without leaked state.

## M3 — complete LTE procedures

- Dedicated Create/Update/Delete Bearer procedures.
- Release Access Bearers and idle downlink detection.
- DDN acknowledgement/failure, duplicate suppression, standard BAR handling,
  bounded QCI-aware buffering, and paging-response telemetry are implemented
  in the SGW reference path; live MME/eNodeB interoperability remains.
- Indirect data forwarding for handover and End Marker handling.
- Durable, fail-closed MME/SGW-C/PGW-C Recovery-counter handling and complete
  stale default-bearer cleanup are implemented; live multi-peer path-failure,
  overload, and restoration interoperability remains.
- Multi-PDN and emergency/unauthenticated UE handling.
- IPv4, IPv6, and IPv4v6 PDN types.

Exit gate: procedure matrix is executable and interoperates with at least two
independent EPC implementations.

## M4 — high-performance SGW-U

- Linux TCX/eBPF GTP-U fast path is implemented for untagged,
  non-fragmented, plain IPv4 G-PDUs, including IPv4 and optional UDP checksum
  repair, exact peer filtering, revision-safe map replacement, per-CPU
  counters, and sampled latency.
- Native/generic XDP, IPv6 outer headers, VLANs, extension headers, MTU policy,
  and fragments remain.
- QER gate/rate enforcement and DSCP marking.
- URR volume/time/event reporting.
- BAR-backed bounded downlink buffering is implemented in the portable Go
  path; the same contract must be implemented in eBPF.
- Map generations, startup reconciliation, per-CPU counters, and live rule
  replacement are implemented for the current TCX subset.
- Reproducible packet-per-second and throughput benchmark suite is implemented
  for the portable chain, SGW-U-only TCX path, and combined TCX SGW-U →
  kernel-GTP PGW-U path. A 1,024-session, 1,400-byte SGW-U uplink has completed
  a provisional 300-second two-host physical-wire run at 9,295.999 Mbps with
  zero measured loss. Mandatory CPU/GC telemetry, the full frame/direction
  sweep, mixed packets, and the physical combined PGW-U gate remain.

Exit gate: no packet outcome differs between the Go reference dataplane and the
eBPF backend for the shared conformance corpus.

## M5 — resilience and operations

- Local SGW-C/PGW-C write-ahead authority, versioned framing, atomic snapshot
  compaction, and exact allocator recovery are implemented.
- Local restart reconciliation across both control planes, PFCP peers, and the
  PGW-U kernel dataplane is implemented and tested at 100,000 sessions.
- In-flight duplicate coalescing is implemented in GTPv2-C and PFCP. The full
  durable chain has passed repeated 1,000-session loss/duplication/reordering
  runs with a control-plane restart and zero failed procedures or leaked state.
- Active/standby SGW-C with fenced ownership.
- A bounded, deterministic regional user-plane selector core now implements
  capacity accounting, sticky restore, explicit regional fallback, and
  ready/draining/unavailable state under concurrent assignment. SGW-C and
  PGW-C also have observable file-controlled admission drains that preserve
  existing sessions. Wiring multiple PFCP clients, persisting the selected
  node in each session journal, association-aware failover, and migration
  policy remain before multi-node operation can be enabled.
- A protected PGW-C bearer-policy API now has owner-only token authentication,
  mandatory TLS 1.3 mTLS off loopback, durable idempotency, audit events, and
  bounded concurrency. Multi-role RBAC and a Gx adapter remain.
- Baseline Prometheus alert rules are implemented; OpenTelemetry and support
  bundles with subscriber redaction remain.
- Hardened systemd units, deterministic release candidates, CycloneDX SBOM,
  provenance, and optional Ed25519 signing are implemented. Rolling upgrade
  automation remains. No container runtime is used or required.

Exit gate: restart, loss, duplication, reordering, peer flaps, and disk-full
fault injection complete without silent state divergence.

## M6 — release hardening

- A 24–72 hour bounded-memory/fault soak harness is implemented; the exact
  signed release still needs to complete the full-duration gate.
- Published compatibility and performance matrix.
- Reproducible builds, SBOM, provenance, and optional signed artifacts are
  implemented; production-key signing and independent dependency review remain.
- Security review, coordinated disclosure process, contributor guide, and
  release migration documentation.
- Lab-to-production checklist with conservative defaults.

Exit gate: release claims are backed by published test methods and raw results.
