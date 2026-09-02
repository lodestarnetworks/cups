# Bare-metal operator guide

This guide covers pre-production installation and isolated `lodestartest`
canaries. PGW-U `production: true` now enforces the kernel-GTP backend, a
separate QCI 1 S5-U path, ownership fencing, and durable state. That
configuration gate is not a production certification: complete fast-path
protocol coverage, live UE/VoLTE interoperability, long-duration soak, signed
release approval, site commissioning, and multi-site resilience remain open.
Do not route the general subscriber APN to this build yet.

No Docker or other container runtime is used or required.

## Build and stage

Build independently on each host or copy a signed release artifact through the
normal deployment channel. The deployment hosts are not assumed to support
direct host-to-host `scp`.

```sh
make verify
make build
sudo install -d -o root -g root -m 0755 /usr/local/lib/sgw-next
sudo install -o root -g root -m 0755 bin/sgw-c bin/sgw-u bin/pgw-c bin/pgw-u /usr/local/lib/sgw-next/
```

Create one non-login service identity and a root-owned configuration directory:

```sh
sudo useradd --system --home-dir /var/lib/sgw-next --shell /usr/sbin/nologin sgw-next
sudo install -d -o root -g sgw-next -m 0750 /etc/sgw-next
```

Install the four unit files from `deploy/systemd/`. They create the persistent
state directory as `/var/lib/sgw-next` mode `0700`. PGW-U is bounded to
`CAP_BPF`, `CAP_NET_ADMIN`, and `CAP_PERFMON`: the first two create kernel-GTP
and TCX resources, while `CAP_PERFMON` selects the privileged verifier path
needed by its bounded policy programs on supported LTS kernels. Load the signed
`gtp` module before starting a kernel-GTP instance because the unit cannot load
kernel modules itself. SGW-U is bounded to `CAP_BPF` and `CAP_NET_ADMIN` so TCX
mode can load maps and links; the implementation attaches only to the two
validated interface names in its configuration. Neither service receives
module-loading or general root privileges.

PGW-U's systemd boundary keeps `/proc/sys` read-only except for
`/proc/sys/net/ipv6/conf`. The kernel backend needs that narrow subtree to
disable unsupported IPv6 on each dynamically created GTP device; all other
kernel tunables remain read-only and the process still receives no
`CAP_SYS_ADMIN` or module-loading capability. A production readiness check must
confirm all three PGW-U capabilities are present in both the ambient and
bounding sets; omitting `CAP_PERFMON` can surface as an eBPF verifier `EFAULT`
rather than a permission error.

## Configure and validate

Start from the files in `configs/`, replace every lab address and secret with
the dedicated `10.x` canary plan, and keep APN scope at `lodestartest`.
Subscriber salts belong in root-readable files rather than inline YAML for a
shared deployment. APN-AMBR values are bits per second.

Enable local control-plane durability:

```yaml
state_file: /var/lib/sgw-next/sgw-c.wal # use pgw-c.wal in PGW-C
state_wal_max_bytes: 4294967296
reconcile_workers: 64
```

PGW-C also has an optional authoritative dedicated-bearer policy listener.
Keep it on loopback when the policy adapter is local; a non-loopback listener
requires TLS 1.3 mutual authentication as well as the bearer token. Provision
the owner-only token before config validation. See `policy-api.md`.

PGW-U kernel mode also needs distinct ownership and state paths:

```yaml
kernel_gtp_ownership_file: /var/lib/sgw-next/pgw-u-kernel.owner
state_file: /var/lib/sgw-next/pgw-u.wal
state_wal_max_bytes: 4294967296
```

For SGW-U, keep syscall batching and every idle-UE queue explicitly bounded.
QCI `0` is the fallback class for bearers without dedicated metadata; QCI `5`
has an independent pool so IMS signalling cannot consume or be trapped behind
the default-data queue:

```yaml
socket_buffer_bytes: 16777216
gtpu_batch_size: 64
downlink_buffering:
  - qci: 0
    max_packets: 65536
    max_bytes: 67108864
    max_packets_per_bearer: 32
    hold_time: 5s
  - qci: 5
    max_packets: 16384
    max_bytes: 16777216
    max_packets_per_bearer: 64
    hold_time: 10s
```

### Optional SGW-U TCX fast path

Leave `fast_path.mode: off` for portable/reference operation. For an isolated
TCX canary, both GTP-U listen addresses must already exist on two distinct
Ethernet interfaces. Configure every permitted ingress peer and the exact
Layer-2 next hop used to reach it:

```yaml
access_gtpu_listen: 10.200.40.1:2152
allowed_access_peers: [10.200.40.2]
core_gtpu_listen: 10.200.50.1:2152
allowed_core_peers: [10.200.50.2]
fast_path:
  mode: tcx
  access_interface: sgwaccess0
  core_interface: sgwcore0
  max_rules: 4000000
  access_neighbours:
    - ip: 10.200.40.2
      mac: 02:00:00:00:40:02
  core_neighbours:
    - ip: 10.200.50.2
      mac: 02:00:00:00:50:02
```

Each neighbour IP set must exactly equal its `allowed_*_peers` set. The MAC is
the Ethernet next-hop MAC, which can be a router rather than the peer itself.
The current release intentionally uses static next-hop entries: verify them
before every start and restart SGW-U after an L2 failover changes a MAC. A
missing next hop leaves that bearer on the Go fallback instead of guessing.

TCX currently accelerates only untagged, non-fragmented IPv4/UDP/2152 packets
with no IPv4 options and a plain GTP-U G-PDU header. GTP-U echo, extension
headers, VLANs, fragments, IPv6, malformed packets, closed QER gates, and
BUFF/BAR traffic continue through the portable path. The embedded BPF objects
mean production builds and hosts need neither clang nor kernel headers. The
objects are generated during development with the pinned `bpf2go` version;
no Docker or runtime compilation is involved.

The SGW uses standard PFCP BARs without private IEs when
`pfcp_enterprise_id: 0` (the safe default). In that mode the BAR ID carries the
bearer's QCI as a standards-valid fallback for buffer-class selection. Exact
private per-bearer QCI/ARP metadata is emitted only when the same non-zero,
registered enterprise identifier is configured on SGW-C and SGW-U. Do not
borrow `10415` (3GPP), `17149` (an unrelated company), or `32473`
(documentation use). Leave this field at zero until Lodestar has its own
registered compatible identifier.

Sxb follows the same safe-default principle. Standard TS 29.244 QERs carry
gates and bit rates but do not carry LTE QCI/ARP. When PGW-C and PGW-U use
`pfcp_enterprise_id: 0`, the explicitly configured `pgwu_qci1_user_ip` /
`qci1_s5_gtpu_listen` F-TEID selects the QCI 1 user plane; PGW-U records QCI 1
and leaves ARP at zero to mean “not present on Sxb”. PGW-C remains authoritative
for the real ARP received over GTPv2-C. This avoids inventing a priority while
keeping the interoperable PFCP path usable. Matching registered enterprise
identifiers may optionally carry exact QCI/ARP metadata between Lodestar peers.

Validate without binding a protocol socket:

```sh
/usr/local/lib/sgw-next/sgw-u --config /etc/sgw-next/sgw-u.yaml --check-config
/usr/local/lib/sgw-next/pgw-u --config /etc/sgw-next/pgw-u.yaml --check-config
/usr/local/lib/sgw-next/pgw-c --config /etc/sgw-next/pgw-c.yaml --check-config
/usr/local/lib/sgw-next/sgw-c --config /etc/sgw-next/sgw-c.yaml --check-config
```

Keep management listeners on the WireGuard/management network. The SGW web UI
contains SGW-C/U telemetry only; PGW metrics remain on the PGW components'
Prometheus endpoints.

For a private dashboard deployment, build `web/` with its pinned package
manager and install the generated `web/dist/standalone/` tree at
`/opt/sgw-next/dashboard/current`. Install and start
`deploy/systemd/sgw-dashboard.service`. It binds only to loopback and can be
viewed through the SSH forward documented in `dashboard.md`; do not publish
port 3000 directly.

## Start order and readiness

The dependency order is PGW-U, PGW-C, SGW-U, then SGW-C. A control process
does not serve GTP until its local state has validated, its user-plane PFCP
association is up, and authoritative replay has completed.

```sh
sudo systemctl enable --now pgw-u.service
sudo systemctl enable --now pgw-c.service
sudo systemctl enable --now sgw-u.service
sudo systemctl enable --now sgw-c.service
```

Check each JSON log for association/reconciliation completion, then query its
management `/healthz` and `/metrics` endpoints from the management network.
Alert on any socket drop, retransmission increase, reconciliation failure,
partial-tail recovery, WAL growth, PFCP grace entry, idle-buffer overflow or
expiry, fast-path fallback/sync/rewrite increase, and excessive forwarding or
DDN-to-paging-response latency in ms. Install and rehearse the baseline rules
in `deploy/prometheus/lodestar-cups-alerts.yaml`; see `alerts-and-soak.md`.

## Controlled admission drain

SGW-C and PGW-C can use a root/operator-controlled file to stop new LTE PDN
creation without interrupting established Internet, IMS, or dedicated bearers.
Configure each process independently:

```yaml
admission_drain_file: /var/lib/sgw-next/sgw-c.drain # pgw-c.drain in PGW-C
admission_poll_interval: 250ms
```

The file path is optional, absolute, and deliberately outside the management
HTTP API. File present means draining; file absent means ready. An unexpected
filesystem error fails closed into draining. Modify Bearer, Release Access
Bearers, dedicated-bearer procedures, usage reporting, and Delete Session
continue normally. The gate never deletes or migrates an existing session.

For planned maintenance, drain SGW-C first, confirm the metric has changed,
and wait for normal session teardown:

```sh
sudo touch /var/lib/sgw-next/sgw-c.drain
# sgw_next_sgwc_admission_draining must be 1
# sgw_next_sgwc_active_sessions must reach 0 before stopping the process
```

Drain PGW-C in the same way before PGW-C maintenance. Its state is exposed as
`lodestar_pgw_admission_draining`. Re-enable admission only after PFCP
association and authoritative replay are healthy:

```sh
sudo rm /var/lib/sgw-next/pgw-c.drain
sudo rm /var/lib/sgw-next/sgw-c.drain
```

Removing a specifically configured drain file is the intended operator action;
do not remove WAL, lock, kernel-owner, or unrelated state files. Admission
draining is not session migration or site failover. A second node must already
be selected by an upstream, association-aware policy before this mechanism can
support rolling regional maintenance.

## Restart and rollback rules

- Stop SGW-C/PGW-C cleanly when possible; never edit or concatenate a live WAL.
- Do not copy a running WAL to another host and treat it as a standby. Local
  `flock` is not a cross-site fence.
- Preserve `.wal` and adjacent `.wal.lock` files together. Never reuse a state
  file with a changed APN, address plan, peer allowlist, pool, or subscriber
  salt; the identity check deliberately rejects it.
- Preserve the PGW-U kernel ownership record. Removing it manually can make
  safe stale-resource identification impossible.
- On rollback to an implementation that cannot consume this state format,
  first drain/delete the `lodestartest` sessions through normal LTE procedures.
  Archive state files with restrictive permissions; do not delete live state
  as an ad-hoc recovery action.

Use the network-namespace scripts in `deploy/benchmark/` for acceptance tests.
They refuse the initial network namespace and report throughput in Mbps and
latency in ms. See `control-plane-recovery.md` and the dated benchmark reports
for the currently proven limits and remaining production gates.

Before a live canary, run `run-isolated-cups-services.sh` as root on the target
host. It uses two disposable namespaces and four veth links to exercise the
real SGW-C/U and PGW-C/U services, SGW-U TCX/URR accounting, PGW-U kernel GTP,
durable restart reconciliation, and active-bearer crash recovery without
installing a host route or binding a live LTE address.

Build, verify, sign, and stage immutable candidates using the process in
`release-process.md`. Unsigned candidates are explicitly marked and are not
approved for production publication.

Before enabling TCX in a canary unit, run
`deploy/benchmark/run-isolated-sgwu-service-smoke.sh`. It starts the real SGW-U
inside a disposable namespace as `nobody`, with no-new-privileges and only
`CAP_BPF`/`CAP_NET_ADMIN`, then verifies graceful shutdown. This checks the
same capability boundary used by the systemd unit without touching a live
interface.
