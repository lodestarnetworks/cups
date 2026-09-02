# User-plane benchmark methodology

This repository follows the Lodestar User Plane Test & Benchmark Specification
v1 supplied on 2026-08-30. It supersedes every earlier ad-hoc capacity claim.

## Current publication status

There is currently **no complete Tier 2 product capacity rating** for SGW-U,
PGW-U, or the combined path. A two-host, real-wire combined SGW-U to PGW-U
large-frame validation has now sustained 8,959.999 Mbps in each independently
measured direction for 300 seconds with zero measured loss. It remains a
provisional engineering result because per-core DUT CPU and GC pause fields
are absent and the mobile frame-size, fallback, policy, and dedicated-host
matrix is incomplete. See `performance.md` for the sanitized result summary.

Earlier VPS, namespace, loopback, and veth runs remain useful functional or
synthetic regression evidence, but the generator and DUT shared a machine and
several runs were shorter than 60 seconds. They must not be published as
production capacity.

The previously discussed 4,684 Mbps observation was a same-host synthetic run
with 488-byte average inner packets, about 1.2 million packets/s aggregate,
zero application-level loss during a 10-second sample, and 100,000 active
session contexts. It is not a physical result and is not a product rating.

## Result classes

- **Tier 0:** no-NIC Go microbenchmarks. Report ns/op, derived single-core pps,
  and allocs/op. These establish only a theoretical software ceiling.
- **Tier 1:** functional correctness. VPS or isolated same-host setups are
  acceptable, but their Mbps and latency are not capacity figures.
- **Tier 2:** two physical machines and a real wire. This is the only tier from
  which a physical capacity figure may be published.
- **Tier 3:** restart, fault, malformed-input, and 24-hour soak evidence.

## Mandatory Tier 2 record

Every row must include the source identity, DUT and generator hardware,
NIC/driver/PCIe details, offload state, CPU governor and clock, CPU/NUMA pinning,
duration, generator-into-null-sink maximum, inner and outer frame sizes, offered
and received pps, offered and received Mbps, loss, NIC drops, application drops,
per-core CPU, GC p99/max, heap, latency p50/p99/p99.9/max, and a stated
bottleneck with evidence.

A run is discarded if the generator and DUT share a machine, GRO/LRO/GSO/TSO
are enabled, generator headroom below 1.5× is unproven, loss is not measured,
duration is under 60 seconds (300 seconds for a headline), CPU scaling remains
active, or the DUT is the shared VPS.

## Private evidence archive

Raw dated reports, packet captures, host output, addresses, routes, and
interface details are retained outside the public repository. The sanitized
figures in `performance.md` preserve the result class and test boundary. A
release claim must still be traceable to privately retained raw evidence and
must meet every applicable rule above.

## Public correction wording

> Quick clarification: the 4,684 Mbps figure in our earlier post was an
> isolated same-host synthetic test, not a physical production benchmark. It
> validated the data path at 100,000 sessions. Two-host, real-wire testing is
> next, and we’ll publish the verified packet rate, frame size, latency and
> zero-loss result.
