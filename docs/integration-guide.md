# Integrating Lodestar CUPS into an LTE EPC

Lodestar CUPS provides the four LTE gateway roles `sgw-c`, `sgw-u`, `pgw-c`,
and `pgw-u`. It is designed to connect to an existing LTE MME/eNodeB and to a
packet data network using the normal EPC reference points.

The implementation uses standards-based GTPv2-C, GTP-U, and PFCP wire
protocols. It implements a defined LTE subset; it does **not** claim complete
3GPP conformance or universal vendor interoperability. End-to-end testing has
primarily used the four Lodestar components together. Qualify every external
MME, SGW, PGW, and user-plane combination before carrying subscriber traffic.

## EPC position

```text
                                      S5/S8-C (GTPv2-C)
 MME ── S11 (GTPv2-C) ── SGW-C ───────────────────────── PGW-C
                              │                              │
                              │ Sxa (PFCP)                   │ Sxb (PFCP)
                              │                              │
 eNodeB ── S1-U (GTP-U) ── SGW-U ── S5/S8-U (GTP-U) ── PGW-U ── SGi ── PDN
```

The MME, HSS, eNodeB, PCRF, IMS, DNS, Internet breakout, NAT/CGNAT, and lawful
intercept functions are not supplied by this repository. The PGW can provide
an IMS APN and P-CSCF addresses to a UE, but it is not an IMS core.

## Interface matrix

| Reference point | Lodestar endpoint | Peer | Protocol and default port | Implemented scope |
|---|---|---|---|---|
| S11 | `sgw-c` | MME | GTPv2-C, UDP 2123 | Echo, default-session create/modify/delete, release access bearers, downlink data notification, recovery handling, and dedicated-bearer relay |
| S5/S8-C | `sgw-c` and `pgw-c` | SGW-C or PGW-C | GTPv2-C, UDP 2123 | Echo, session create/modify/delete, PGW-initiated create/update/delete bearer, and recovery handling |
| Sxa | `sgw-c` and `sgw-u` | SGW-C or SGW-U | PFCP, UDP 8805 | Association, heartbeat, session establish/modify/delete, PDR/FAR/QER/URR/BAR, downlink notification, and usage reports |
| Sxb | `pgw-c` and `pgw-u` | PGW-C or PGW-U | PFCP, UDP 8805 | Association, heartbeat, session establish/modify/delete, PDR/FAR/QER/URR, and usage reports |
| S1-U | `sgw-u` | eNodeB | GTP-U, UDP 2152 | IPv4 G-PDU forwarding, Echo, bounded downlink buffering, and portable parsing of optional/extension headers |
| S5/S8-U | `sgw-u` and `pgw-u` | SGW-U or PGW-U | GTP-U, UDP 2152 | IPv4 G-PDU forwarding and Echo |
| SGi | `pgw-u` Linux GTP device | Packet data network | Routed IPv4 | UE-prefix route to a private PDN or operator-managed Internet/NAT edge |
| Management | all four processes | Operator tooling | HTTP/JSON and Prometheus, configured TCP port | Project-specific health, metrics, events, and dashboard data; not a 3GPP interface |
| Bearer policy | `pgw-c` | Policy adapter | HTTPS/JSON with token and mTLS off loopback | Project-specific dedicated-bearer API; not Diameter Gx or Gy |

Normative protocol definitions are maintained by 3GPP and published by ETSI:

- [3GPP TS 29.274 / ETSI TS 129 274: GTPv2-C](https://www.etsi.org/deliver/etsi_ts/129200_129299/129274/18.06.00_60/ts_129274v180600p.pdf)
- [3GPP TS 29.281 / ETSI TS 129 281: GTP-U](https://www.etsi.org/deliver/etsi_ts/129200_129299/129281/18.01.00_60/ts_129281v180100p.pdf)
- [3GPP TS 29.244 / ETSI TS 129 244: PFCP](https://www.etsi.org/deliver/etsi_ts/129200_129299/129244/18.10.00_60/ts_129244v181000p.pdf)
- [3GPP TS 23.214 / ETSI TS 123 214: CUPS architecture](https://www.etsi.org/deliver/etsi_ts/123200_123299/123214/14.08.00_60/ts_123214v140800p.pdf)
- [3GPP TS 23.401 / ETSI TS 123 401: EPS architecture](https://www.etsi.org/deliver/etsi_TS/123400_123499/123401/15.05.00_60/ts_123401v150500p.pdf)

The standards define much more than the currently implemented subset. The
matrix above, tests in this repository, and the open limitations below—not the
presence of a codec or an IE constant—define product support.

## Supported deployment combinations

### All four Lodestar gateway processes

This is the reference and best-tested arrangement. Connect the existing MME
to `sgw-c` over S11, eNodeBs to `sgw-u` over S1-U, and route the UE prefixes
from the `pgw-u` Linux GTP device towards the selected packet data network.
`sgw-c` controls `sgw-u` over Sxa; `pgw-c` controls `pgw-u` over Sxb.

### Lodestar SGW with an external PGW

Run `sgw-c` and `sgw-u` together. Point `sgw-c` at the external PGW-C over
S5-C and permit the external PGW-U as an S5-U peer on `sgw-u`. The Lodestar
Sxa pair remains internal. Validate the external PGW's accepted GTPv2-C IEs,
PCO handling, recovery counter behaviour, bearer procedures, and GTP-U peer
address selection in an isolated APN.

### External SGW with the Lodestar PGW

Run `pgw-c` and `pgw-u` together. Permit the external SGW-C on `pgw-c` S5-C
and the external SGW-U on `pgw-u` S5-U. The Lodestar Sxb pair remains
internal. Validate the external SGW's APN encoding, control/user F-TEIDs,
retransmission behaviour, dedicated-bearer procedures, PCO relay, and recovery
counter handling.

Directly pairing a Lodestar control plane with a third-party user plane over
Sxa or Sxb is not currently a supported deployment. PFCP is standards-based,
but the supported IE profile and behaviour have only been qualified between
the matching Lodestar C/U processes.

## Current LTE feature boundary

Implemented for integration testing:

- IPv4 PDN sessions with one or more exact APN profiles;
- UE IPv4 allocation, IPv4 DNS PCO, IPv4 link MTU, P-CSCF IPv4 PCO, and
  APN-AMBR;
- default EPS bearer lifecycle, idle release/resume, detach, and local restart
  recovery;
- PGW-initiated dedicated bearer create/update/delete for the implemented
  directional IPv4 TFT and QoS subset;
- QCI/ARP handling, bitrate gates, usage counters, and QCI 5 downlink-buffer
  isolation;
- multiple APN-to-PGW-C routes in SGW-C and multiple APN/UE-pool profiles in
  PGW-C and PGW-U; and
- local durable state, retransmission/idempotency handling, peer allowlists,
  Prometheus metrics, and maintenance admission drain.

Not currently supported or not yet qualified:

- IPv6 or IPv4v6 PDN sessions, NAT64, or deterministic CGNAT;
- Diameter Gx/Gy, online charging, or a PCRF implementation;
- S8 roaming security/profile enforcement, PMIP S5/S8, or IPsec provisioning;
- indirect data forwarding and the complete handover procedure set;
- emergency/unauthenticated attach, 2G/3G gateway interfaces, or 5G N-interfaces;
- cross-site active/standby state replication and quorum fencing;
- complete TCX fast-path coverage for VLAN, fragmented, IPv6, and every
  extension-bearing packet; unsupported packets deliberately use the portable
  path; and
- a third-party interoperability or formal conformance certification matrix.

The optional `pfcp_enterprise_id` preserves Lodestar QCI/ARP metadata in a
private PFCP IE. Leave it at `0` for the standards-only profile. If it is used,
configure the same operator-owned IANA Private Enterprise Number on each side;
do not use 3GPP's reserved value.

## Network and host prerequisites

- Linux for production-shaped user planes. PGW-U production mode requires the
  Linux `gtp` kernel module and generic-netlink family.
- Root only for installation and initial network preparation. The supplied
  systemd units run with restricted service identities and capabilities.
- IP reachability between each peer pair. Do not NAT GTPv2-C, PFCP, or GTP-U
  inside the EPC unless the complete F-TEID and return-path behaviour is
  understood and tested.
- UDP 2123 between MME/SGW-C and SGW-C/PGW-C; UDP 8805 within each C/U pair;
  UDP 2152 between eNodeB/SGW-U and SGW-U/PGW-U.
- A unique routed IPv4 prefix for every APN profile. PGW-C and PGW-U must use
  identical APN-to-prefix/gateway mappings.
- An SGi routing or NAT policy maintained outside Lodestar CUPS. Remote packet
  networks must route every UE prefix back through the PGW-U host.
- Persistent local storage for SGW-C, PGW-C, and production PGW-U state. Do
  not place authority journals on ephemeral storage.
- Working DNS, P-CSCF/IMS, and packet data network services where the APN
  requires them.

No container runtime is required or used by the supplied build and service
workflow.

## Addressing worksheet

Assign separate subnets or VRFs according to the operator's security design.
These are roles, not required CIDRs:

| Plane | Endpoints to assign |
|---|---|
| S11 | MME, SGW-C |
| S5/S8-C | SGW-C, PGW-C |
| Sxa | SGW-C, SGW-U |
| Sxb | PGW-C, PGW-U |
| S1-U | eNodeB peers, SGW-U access address |
| S5/S8-U | SGW-U core address, PGW-U user-plane address |
| SGi | PGW-U GTP device gateway, UE pool, upstream PDN next hop |
| Management | Four component listeners, dashboard/reverse proxy, Prometheus |

The files under `configs/` contain a self-consistent private `10.250.0.0/16`
example. Replace every address, APN, subscriber salt, path, interface name,
and capacity limit before deployment. Listener addresses are local binds;
`*_advertise` addresses are encoded for peers and must be reachable from them.

## Configuration sequence

1. Copy the four `configs/*.lab.yaml` files into an operator-private
   configuration repository. Never commit live addresses, credentials,
   subscriber identifiers, or salts to this public repository.
2. Configure `sgw-c` S11 and S5-C addresses, MME allowlist, PGW-C default or
   per-APN routes, Sxa peer, and the two SGW-U GTP-U advertised addresses.
3. Configure `sgw-u` Sxa peer, S1-U/S5-U listeners, and exact eNodeB and PGW-U
   source-address allowlists. Start with `fast_path.mode: off` for interop.
4. Configure matching `pgw-c` and `pgw-u` APN profiles, UE prefixes, gateways,
   PGW-U S5-U address, Sxb pair, DNS/P-CSCF addresses, MTU, and AMBR.
5. Enable authority files on persistent storage and use a random
   `subscriber_salt_file` readable only by the service account.
6. Keep every management listener on a management network or loopback behind
   an authenticated reverse proxy. Do not expose it to subscriber, radio, or
   public networks.
7. Validate all four files before changing any network route:

   ```sh
   ./bin/sgw-c --config /etc/lodestar-cups/sgw-c.yaml --check-config
   ./bin/sgw-u --config /etc/lodestar-cups/sgw-u.yaml --check-config
   ./bin/pgw-c --config /etc/lodestar-cups/pgw-c.yaml --check-config
   ./bin/pgw-u --config /etc/lodestar-cups/pgw-u.yaml --check-config
   ```

8. Start user planes before control planes. Confirm PFCP association and
   health endpoints before allowing an MME to select the SGW.
9. Add the APN and its PDN subscription to the HSS using the existing MME/HSS
   workflow. The APN spelling must exactly match the PGW-C profile.
10. Route one isolated APN or test subscriber first. Preserve the old gateway
    route and prepare an atomic rollback before attach testing.

The [operator guide](operator-guide.md) covers Linux capabilities, kernel GTP,
TCX, durable state, systemd, monitoring, and rollback in more detail.

## Minimum interoperability test

Do not expand beyond the isolated APN until all of the following pass with
packet captures and component metrics retained outside the public repository:

1. GTPv2-C Echo and PFCP association/heartbeat in both directions.
2. Fresh attach and default bearer activation.
3. Uplink and downlink IPv4 traffic with the negotiated MTU and DNS.
4. Idle transition, downlink data notification/paging, and bearer resume.
5. Detach, immediate reattach, APN rejection, and unknown-TEID rejection.
6. MME, SGW-C, PGW-C, SGW-U, and PGW-U restart tests, one component at a time.
7. Duplicate, delayed, reordered, and lost control packets within the planned
   transport fault envelope.
8. Dedicated-bearer create/update/delete and repeated VoLTE call cycles when
   IMS is in scope.
9. Sustained traffic below the accepted zero-loss capacity, verifying Mbps,
   p95/p99 latency in ms, packet loss, kernel queue drops, and rollback.
10. A complete teardown leaving zero control sessions, PFCP sessions, kernel
    PDP contexts, UE leases, or buffered packets.

Record the exact peer products and versions. Passing with one peer does not
establish compatibility with another implementation or release.

## Operational checks

Each process exposes `/healthz` and `/metrics` on its configured management
listener. Before admitting sessions, verify:

- SGW-C and PGW-C report their PFCP associations as established;
- control-plane recovery and reconciliation queues are empty;
- user-plane backend/capability metrics match the intended mode;
- receive-queue, retransmission, malformed-packet, drop, and rule-install
  counters are stable at zero or an understood baseline; and
- SGi return routes and firewall rules are present without broad source NAT on
  EPC control or tunnel networks.

Dashboard and JSON APIs are observability aids only. Forwarding and recovery
must continue when the dashboard is unavailable.

## Security boundary

Treat GTPv2-C, PFCP, and GTP-U as private-network protocols. Enforce exact peer
source allowlists at routing/firewall and application layers; isolate control,
user, management, and SGi traffic; and protect inter-site links according to
the operator threat model. This repository does not provision an inter-site
security layer.

Review [SECURITY.md](../SECURITY.md), the
[private deployment boundary](private-deployment-boundary.md), and the
[release process](release-process.md) before making a build reachable by an
external peer.
