# Performance evidence

This page records sanitized engineering results for the reusable Lodestar CUPS
source tree. Raw host output, addresses, interface names, routes, and captures
are retained in the operator's private evidence archive.

These figures are not a product capacity rating or subscriber-count promise.
They describe specific packet sizes, offered loads, hardware, software
revisions, and test durations. Capacity must be requalified on the target host
with the intended traffic mix and a zero-loss acceptance point.

## Accepted physical-link result

The complete SGW-U to PGW-U path was tested with an independent generator and
validator across a dedicated full-duplex 10,000 Mbps Ethernet link. Traffic
entered as GTP-U, traversed the SGW-U TCX path and PGW-U kernel-GTP path, and
exited as plain IPv4; the reverse path was exercised independently.

| Profile | Result |
|---|---|
| Fixed 1,400-byte subscriber packets, one direction at a time | 8,959.996 Mbps received in each tested direction for 60 seconds, with zero measured packet loss |
| Simultaneous default-data and QCI 1 traffic | Approximately 9,090 Mbps on each physical-link direction, with zero measured packet loss |
| QCI 1 latency during the mixed profile | 1 ms p95 and 3 ms p99 |
| Gateway, NIC, qdisc, and softnet drop deltas at the accepted point | Zero |

The next offered-rate steps above the accepted point produced hardware receive
drops. The quoted ceiling is therefore the accepted zero-loss result for that
host/link/profile, not the line rate of every deployment.

## Software-path evidence

The following tests used isolated namespaces or same-host endpoints. They are
regression and headroom evidence, not physical-NIC capacity:

| Test | Result and boundary |
|---|---|
| Linux kernel-GTP PGW-U | 30,514.60 Mbps uplink and 34,007.36 Mbps downlink at zero measured loss on a fixed-packet, same-host software path |
| SGW-U TCX only | 24,861.744–25,179.270 Mbps aggregate at zero measured loss across three hard-saturation repeats; PGW-U and a physical NIC were not in the path |
| Complete TCX SGW-U to kernel-GTP PGW-U | At least 12,432.806 Mbps aggregate at zero measured loss across three bidirectional repeats; same-host endpoints and fixed packets were used |
| Portable Go SGW-U to kernel-GTP PGW-U | At least 2,673.293 Mbps aggregate at zero measured loss in the accepted regression profile |

An overload result with high offered Mbps and substantial loss is not an
accepted capacity point and is deliberately omitted from the headline values.

## Control-plane evidence

SGW-C and PGW-C do not forward subscriber Mbps. Their useful measures are
procedures per second, latency in ms, restart recovery, and leaked state.

| Test | Result |
|---|---|
| Volatile full-chain create lifecycle | At least 7,550 Create Sessions/s, approximately 14.1 ms p95, with no leaked state in the accepted runs |
| Fsync-durable 100,000-session lifecycle | 2,710.40 creates/s, 39.39 ms p95, exact lease/state restore, and zero leaked state |
| Durable restore and PFCP reconciliation of 100,000 sessions | 16,330.046 ms |
| Faulted 1,000-session lifecycle | Three accepted runs with 2% loss, 1% duplication, 25% reordering, and a mid-run control restart; all 9,000 procedures completed and final state was empty |
| Cloud-host admission/restart regression | 478.59 Mbps uplink and 478.48 Mbps downlink average at zero measured loss while drain/recovery tests completed; observed component recovery windows were 139–5,584 ms |

The cloud result reflects that virtual host and does not supersede the physical
10,000 Mbps link result.

## Reproducing a result

Use the root-only scripts under `deploy/benchmark/` on an isolated host or
dedicated test interfaces. No Docker or other container runtime is used.

For a capacity statement, record at minimum:

- source revision and release digest;
- CPU model/topology, memory, kernel, NIC, driver, firmware, queue count, IRQ
  placement, MTU, and offload state;
- complete packet-size and direction mix, GTP-U extension/fragment/VLAN mix,
  bearer count, TEID/peer diversity, offered pps, offered Mbps, and duration;
- sender and receiver packet counts from independent endpoints;
- gateway counters plus NIC, qdisc, softnet, UDP receive-queue, and kernel-GTP
  deltas;
- p50, p95, p99, and maximum latency in ms for a separate probe flow; and
- CPU, memory, thermal, disk/WAL, and reconciliation behaviour during and after
  the run.

Increase load in bounded steps and publish the highest repeatable point with
zero unexplained loss. A sender's requested Mbps, or a counter from only one
side of the path, is not a throughput result.

See [benchmark-methodology.md](benchmark-methodology.md) for the acceptance
rules and [alerts-and-soak.md](alerts-and-soak.md) for endurance monitoring.
