# Lodestar CUPS

Lodestar CUPS is an LTE-only mobile-core gateway containing separated SGW-C,
SGW-U, PGW-C, and PGW-U processes. Control, protocol, configuration, and
telemetry are written in Go. PGW-U has a real Linux kernel-GTP backend. SGW-U
has a revision-safe Linux TCX/eBPF path for plain IPv4 G-PDUs plus the portable
Go correctness/fallback path. Physical-wire default and QCI 1 forwarding has
now passed at line-rate-class load. Durable PFCP usage-report reconciliation
and a protected authoritative bearer-policy API are implemented, but protocol
coverage, multi-site resilience, endurance soak, signed-release approval, and
live LTE interoperability still prevent a production claim.

The repository is pre-release engineering software. It has passed substantial
isolated and bare-metal qualification, but it is not yet production-ready and
must not replace a live path without an operator-controlled canary, tested
rollback, and independent review.

> **Benchmark status:** the complete SGW-U to PGW-U path sustained 8,959.996
> Mbps of 1,400-byte subscriber traffic for 60 seconds in each independently
> measured direction over a dedicated 10,000 Mbps physical link, with zero
> measured packet loss. A simultaneous default-data plus QCI 1 profile loaded
> each link direction to about 9,090 Mbps with zero measured loss; QCI 1
> p95/p99 latency was 1/3 ms. This is pre-production engineering evidence, not
> a product capacity or VoLTE SLA rating. See `docs/performance.md` and
> `docs/benchmark-methodology.md`.

## Current foundation

- SGW-C and SGW-U telemetry/state contracts.
- A deterministic local lab generator for repeatable UI and API testing.
- JSON endpoints for SGW-C, SGW-U, dashboard, health, and event data.
- Prometheus-compatible metrics exposition.
- Defensive GTPv2-C, PFCP, and GTP-U header codecs with tests.
- Revision-safe SGW-C session/bearer state and SGW-U PFCP rule stores.
- Fsync-before-acknowledgement SGW-C/PGW-C authority journals with strict
  single-owner fencing, crash-tail recovery, atomic snapshot compaction,
  durable UE-lease restore, and bounded parallel PFCP reconciliation.
- Interface-correct GTPv2 Recovery IE stamping plus durable MME, SGW-C, and
  PGW-C peer counters. A changed counter is acknowledged only after stale
  SGW-C/U and PGW-C/U state has been removed or an idempotent retry succeeds.
- S5-C PGW lifecycle, bounded IPv4 leasing, Sxb rules, and a development-only
  PGW-U forwarding path for the `lodestartest` APN.
- Handset-facing IPv4 PCO/IPCP DNS and link-MTU negotiation, APN-AMBR response
  handling, and end-to-end default-bearer bitrate preservation.
- PFCP association grace, no-new-session gating, atomic authoritative replay,
  stale-rule cleanup, and grace countdown metrics.
- Standard PFCP BAR lifecycle, bounded per-QCI/per-bearer idle downlink
  buffering, QCI 5 priority release, ARP-bearing DDN, and DDN-to-paging latency
  telemetry.
- Durable PGW-initiated dedicated-bearer signalling with directional IPv4 TFT
  classification, a separate QCI 1 kernel-GTP path, gate and bitrate QERs, and
  per-bearer volume URR telemetry. Both user planes emit ordered PFCP usage
  reports and both control planes durably reconcile duplicate, gap, conflict,
  restart-epoch, and crash-tail state without gating forwarding.
- A separate authenticated PGW-C policy API with durable idempotency, strict
  TFT/QoS validation, bounded concurrency, a loopback-only safe default, and
  mandatory TLS 1.3 mutual authentication away from loopback.
- Batched Linux UDP receive/transmit in the portable SGW-U path, exercised by
  a historical same-host 1,200-byte regression test. Its Mbps observation is
  not a physical-NIC or production sizing result.
- Optional TCX/eBPF SGW-U ingress forwarding for untagged, non-fragmented,
  plain IPv4 G-PDUs, with exact peer allowlists, generation-safe rule flips,
  checksum repair, per-CPU counters, sampled handler latency, and deliberate
  portable fallback for unsupported packets and buffered bearers.
- Historical same-host TCX and complete-chain saturation experiments are kept
  as regression evidence. Their veth generator and receivers shared the DUT,
  so their Mbps and latency observations must not be quoted as capacity.
- Direct Linux kernel-GTP PGW-U context programming, outer-peer filtering,
  checksummed fsync-before-acknowledgement restart state, and ownership-fenced
  recovery of stale links and firewall tables after an abrupt process death.
- Isolated end-to-end CUPS user-plane and full GTPv2-C/PFCP/kernel control-plane
  capacity harnesses with packet-loss, latency-ms, and cleanup accounting.
- Strict YAML component configuration with `--check-config`.
- A dedicated SGW-C/SGW-U operator dashboard in `web/`.
- Reproducible no-Docker release tooling, CycloneDX SBOM/provenance, optional
  Ed25519 signing, Prometheus alert rules, and an isolated 24–72 hour soak
  harness.

## Local development

Run the Go lab API:

```sh
go run ./cmd/sgw-lab
```

Run the dashboard in another terminal:

```sh
cd web
pnpm dev
```

The API listens on `127.0.0.1:8080` and the dashboard development server uses
`http://localhost:3000` by default.

For root-only, no-Docker benchmarks that cannot touch a live interface, build
the binaries and use the scripts in `deploy/benchmark/`. Each creates a
temporary network namespace with only `10.x` endpoints, reports throughput in
Mbps or procedure latency in ms, then removes only its own namespace. The full
CUPS scripts are `run-isolated-cups-dataplane.sh` and
`run-isolated-cups-control.sh`. The older SGW-only script accepts normal
`sgw-e2e` flags, for example `--target-pps 0 --throughput-duration 10s`.
If the host has not installed `deploy/sysctl/90-sgw-next.conf`, the explicit
first flag `--tune-host-sockets` temporarily applies those five socket limits
and restores every original value during cleanup.

The SGW-U TCX-only wrapper is `run-isolated-sgwu-ebpf.sh`; the accelerated
complete-chain wrapper is `run-isolated-cups-ebpf-dataplane.sh`. They require
root to load/attach the embedded BPF object and create kernel-GTP resources,
but use only newly created namespace interfaces. Normal builds and runtime do
not require clang or kernel headers, and no container runtime is used.
`run-isolated-sgwu-service-smoke.sh` additionally proves the real daemon can
load TCX as a non-root identity with only `CAP_BPF` and `CAP_NET_ADMIN`.
`run-isolated-cups-services.sh` starts all four production-shaped daemons
across two namespaces, forces traffic through SGW-U TCX and PGW-U kernel GTP,
and crash-recovers each daemon while a bearer remains active.

Sanitized physical-link, software-path, control-plane, and cloud-host results
are in `docs/performance.md`. Raw logs, captures, host identifiers, addresses,
routes, and interface details remain in the operator's private evidence
archive and are deliberately excluded from the public source tree.

## Scope

The near-term scope is 4G LTE only: S11 and S5/S8 GTPv2-C, Sxa PFCP, and S1-U
plus S5/S8-U GTP-U. Five-G core functions and interfaces are intentionally out
of scope.

The on-wire gateway interfaces use the standard LTE protocols and ports:
GTPv2-C on UDP 2123, PFCP on UDP 8805, and GTP-U on UDP 2152. Lodestar CUPS
implements a documented subset rather than claiming complete 3GPP conformance
or universal vendor interoperability. The management API, dashboard, and
optional bearer-policy API are project-specific interfaces. See the
[`docs/integration-guide.md`](docs/integration-guide.md) interface matrix,
supported deployment combinations, configuration sequence, and interop test
plan before connecting an external core component.

See `docs/architecture.md` and `docs/roadmap.md` for the design and delivery
gates. Control-plane durability is documented in
`docs/control-plane-recovery.md`; kernel-backend ownership and restart behavior
are documented in `docs/kernel-gtp-recovery.md`. `docs/licensing.md` records
the Apache-2.0 release licence and the clean-room boundary. The protected controller
contract is in `docs/policy-api.md`; release and endurance gates are in
`docs/release-process.md` and `docs/alerts-and-soak.md`.

## Safety and status

All UDP protocol input is treated as untrusted. Wire decoders are bounded and
state updates are transactional. Shipped component configurations use 10.x
addresses; the deterministic UI-only lab binds to loopback. See `SECURITY.md`
before testing against any external peer. Live operator overlays and raw
subscriber evidence are deliberately excluded; see
`docs/private-deployment-boundary.md`.
