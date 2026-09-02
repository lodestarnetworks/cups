# SGW-C / SGW-U dashboard

The dashboard monitors only the Serving Gateway being built in this repository.
MME and PGW entries are peer observations made by SGW-C; they are not presented
as independently managed products.

## SGW-C surfaces

- active sessions and EPS bearers;
- in-flight GTPv2-C transactions;
- procedure request/success/failure counts and latency;
- retransmissions, collision decisions, and S11/S5-C/Sxa kernel receive-queue drops;
- S11, S5/S8-C, and Sxa peer state and RTT;
- restart/recovery state and session reconciliation;
- pending paging requests and per-QCI/per-eNodeB DDN-to-paging-response latency
  histograms in ms;
- bounded, redacted component events.

## SGW-U surfaces

- PFCP association, session state, and PFCP kernel receive-queue drops;
- installed PDR, FAR, QER, URR, and BAR counts;
- uplink/downlink bits and packets per second;
- per-rule drops, unknown TEIDs, and forwarding latency;
- active dataplane mode, fast-path forwarded packets/bytes, fallback packets,
  map-sync failures, in-kernel rewrite errors, and sampled forwarding p95 in
  ms;
- QoS gates, current idle-buffer
  packets/bytes, and cumulative enqueue/release/expiry/overflow/purge counters
  by QCI;
- installed PDR/FAR/QER/URR totals. Rate enforcement and durable PFCP report
  delivery remain separately observable and must not be inferred merely from
  QER/URR counts.

## Data labelling

The UI has three explicit source states:

- `preview`: static fallback content while the local API is unavailable;
- `simulated-lab`: deterministic values from `cmd/sgw-lab`;
- `live`: values emitted by real SGW-C and SGW-U processes.

Generated data must never be labelled live. Raw IMSI, MSISDN, IMEI, and user IP
addresses are excluded from default dashboard payloads.

## Live telemetry transport

The browser reads a same-origin, read-only `/sgw-api` route. That route permits
only the documented health, dashboard, component, event, and Prometheus GET
endpoints and forwards them to `SGW_API_UPSTREAM`. It does not accept arbitrary
paths or state-changing methods.

Keep the SGW-C and SGW-U management listeners on loopback. During remote
development, forward the SGW-C listener over SSH and point
`SGW_API_UPSTREAM` at that local tunnel. A native deployment should place the
dashboard behind HTTPS and authentication while retaining the loopback-only
upstream. Never expose ports 8080 or 8081 directly to the internet.

The unit in `deploy/systemd/sgw-dashboard.service` runs the
standalone dashboard as the unprivileged `sgw-next` identity, binds only to
`127.0.0.1:3000`, and permits outbound connections only to localhost. Access
it from an operator workstation with a loopback SSH forward:

```sh
ssh -N -L 127.0.0.1:3000:127.0.0.1:3000 gateway-host
```

Then open `http://localhost:3000`. The browser never receives access to the
private management ports; the dashboard server proxies only its fixed,
read-only endpoint allowlist.

## Visual direction

The dashboard uses an independent SGW Next identity with a visual direction
inspired by the public Lodestar Networks site: flat black/cream surfaces,
electric blue, coral status accents, square data tables, large technical
headlines, and monospace labels. No Lodestar source code, copy, logo, or graphic
asset is included.
