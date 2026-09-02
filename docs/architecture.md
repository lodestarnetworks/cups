# Architecture

## Scope

SGW Next is a 4G LTE Serving Gateway with an explicit control/user-plane split.
The project targets S11, S5/S8-C, Sxa, S1-U, and S5/S8-U. It does not implement
5G core interfaces or network functions.

The repository now contains an executable LTE default-bearer vertical slice,
including SGW-C, SGW-U, PGW-C, PGW-U, PFCP, GTPv2-C, a Linux kernel-GTP PGW-U
backend, telemetry, and the operator dashboard. It has carried synthetic and
isolated test traffic but is not approved to replace the live subscriber path.

## Process boundary

```text
                                      S5/S8-C / GTPv2-C / UDP 2123
 MME -- S11 / GTPv2-C / UDP 2123 -- SGW-C ------------------------- PGW-C
                                         |                            |
                                         | Sxa / PFCP / UDP 8805      | Sxb / PFCP / UDP 8805
                                         |                            |
 eNB -- S1-U / GTP-U / UDP 2152 ----- SGW-U -- S5/S8-U / GTP-U -- PGW-U -- SGi -- PDN
```

SGW-C is the only owner of LTE session and EPS bearer control state. SGW-U is
the owner of Sxa rules and SGW forwarding state. PGW-C owns PDN session and
address-allocation authority; PGW-U owns Sxb rules, kernel-GTP contexts, and
SGi-facing forwarding state. A control plane never edits dataplane maps
directly: SGW-C programs SGW-U over Sxa and PGW-C programs PGW-U over Sxb.
User planes never invent LTE session policy.

See `integration-guide.md` for the implemented protocol subset, external-peer
deployment combinations, and the distinction between 3GPP interfaces and the
project-specific management/policy APIs.

## Repository layout

- `cmd/sgw-lab`: local SGW-C/SGW-U telemetry and API harness.
- `internal/sgwc/session`: revision-safe session and bearer ownership store.
- `internal/sgwu/rules`: transactional PDR/FAR/QER/URR/BAR store.
- `internal/sgwu/fastpath`: optional Linux TCX/eBPF SGW-U forwarding backend.
- `internal/telemetry`: API contracts shared by the components and dashboard.
- `internal/api`: loopback-first JSON and Prometheus endpoints.
- `internal/lab`: deterministic component telemetry for repeatable tests.
- `pkg/gtpv2`: bounded GTPv2-C header parsing and encoding.
- `pkg/pfcp`: bounded PFCP header parsing and encoding.
- `pkg/gtpu`: bounded GTP-U parsing, encoding, and extension-header walking.
- `web`: SGW-C/SGW-U operator dashboard.
- `internal/userplane`: bounded deterministic placement primitives for future
  regional SGW-U/PGW-U pools. The selector is deliberately not wired into the
  single-peer production path until selected-node ownership is added to the
  durable session formats and PFCP reconciliation.

## SGW-C state model

Every session has an opaque subscriber key, APN, S11/S5 control F-TEIDs, one
default bearer, optional dedicated bearers, and a revision. The store indexes
sessions by internal ID, S11 TEID, and subscriber/APN owner. Updates use an
expected revision and are committed only after the complete candidate session
passes validation. This avoids partially applied bearer changes and prevents
stale procedure handlers from overwriting newer state.

In durable mode the validated transition is checksummed and `fsync`ed before
the in-memory store changes. Recovery rebuilds every index and allocator,
replays authoritative PFCP state before GTP service begins, and uses atomic
snapshot compaction to bound obsolete journal history. PGW-C applies the same
rules to PDN sessions and restores exact UE IPv4 leases. See
`control-plane-recovery.md` for fencing and failure semantics. Cross-host
replication and quorum-backed active/standby fencing remain pending.

Raw IMSIs are not part of the telemetry model. The control plane will hash or
otherwise pseudonymise subscriber identifiers before they enter diagnostics.

## SGW-U rule model

A PFCP session contains PDR, FAR, QER, URR, and BAR maps. Each update is cloned,
mutated, validated as a complete graph, and committed atomically. Validation
currently enforces:

- non-zero CP- and UP-SEIDs;
- at least one PDR;
- valid PDR-to-FAR/QER/URR references;
- valid FAR-to-BAR references;
- valid local and outer TEIDs;
- no contradictory DROP/FORWARD action;
- forwarding FARs have a usable outer header;
- URRs select at least one measurement method;
- immutable packet lookup snapshots are derived only from a validated graph.

FARs using BUFF/NOCP retain complete GTP-U wire packets in hard-bounded,
per-QCI and per-bearer queues. QCI 5 has an independent priority pool. BAR
delay, queue expiry, overflow, purge, and ordered release are all explicit;
buffer pressure never grows without a configured packet, byte, bearer, and
time bound.

## Dataplane strategy

The executable SGW-U dataplane has two coordinated backends. The portable Go
implementation remains the correctness oracle and handles GTP-U echo, BAR/DDN
buffering, unsupported headers, and fast-path misses. On Linux it batches GTP-U
receive and transmit syscalls while retaining per-datagram receive-overflow
accounting; other platforms retain a bounded one-packet fallback.

The optional Linux fast path attaches TCX programs to access- and core-side
ingress. It currently consumes only untagged Ethernet, IPv4 without options or
fragments, UDP/2152, and plain GTP-U G-PDUs. Exact ingress peer maps are checked
before tunnel lookup. Revisioned tunnel, active-generation, and packet-rule
maps stage a complete replacement before the active revision flips; a failed
update deactivates that session so traffic falls back to Go rather than using
stale forwarding. Rewrites cover Ethernet addresses, outer IPv4 addresses and
checksum, UDP source port/checksum, and TEID. Per-CPU counters and sampled
handler-latency buckets are merged into the normal SGW-U telemetry.

PFCP rules selecting BUFF/DROP, a closed QER gate, IPv6, VLANs, IPv4 options,
fragments, extension-bearing GTP-U, malformed packets, or an unconfigured next
hop are deliberately left for the portable path. Unauthorized valid G-PDUs
and failed in-kernel rewrites are dropped. PGW-U independently uses direct
Linux kernel-GTP/generic-netlink. The combined TCX SGW-U → kernel-GTP PGW-U
software path has an isolated zero-loss result; mixed traffic, multiple
sessions under load, and a physical-interface result remain delivery gates.

## Management and telemetry

The current lab API exposes:

- `GET /healthz`
- `GET /api/v1/dashboard`
- `GET /api/v1/sgwc`
- `GET /api/v1/sgwu`
- `GET /api/v1/events?limit=N`
- `GET /metrics`

The listener binds to `127.0.0.1` by default. Production management will add
mTLS, role-based access, audit records, pagination, and explicit redaction.

## Reliability rules

- Decode before state mutation.
- Bound every collection and timer queue.
- Make retransmissions idempotent.
- Keep procedure ownership explicit.
- Reject stale revisions instead of applying last-writer-wins.
- Reconcile PFCP state before advertising a recovered session as active.
- Separate desired rule state from installed dataplane state.
- Fence each kernel-GTP owner with a locked mode-0600 identity file; recover a
  stale interface or firewall only when its full 256-bit token matches.
- Fence SGW-C/PGW-C journal ownership locally, commit state before protocol
  acknowledgement, and fail closed after any durable write ambiguity.
- Persist GTPv2 peer Recovery counters separately, stamp the sending node's
  counter on every relayed request, and withhold restart acknowledgement until
  all downstream and local contexts are consistently deleted.
- Never use dashboard availability as a forwarding dependency.
