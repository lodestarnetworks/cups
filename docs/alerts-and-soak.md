# Alerting and endurance qualification

`deploy/prometheus/lodestar-cups-alerts.yaml` contains the baseline production
alerts for component/PFCP availability, durable-state and PFCP usage-report
integrity, socket/queue drops, internal latency, kernel-policy drift, and the
dedicated-bearer policy API. Validate the file during every build:

```sh
go run ./cmd/lodestar-alert-check \
  deploy/prometheus/lodestar-cups-alerts.yaml

PROMTOOL=/absolute/path/to/promtool \
  deploy/prometheus/test-alert-rules.sh
```

The first command enforces Lodestar's rule schema and mandatory operational
metadata. The second uses Prometheus itself to parse the expressions and run
the checked-in alert fixtures. `promtool` is therefore a release-qualification
dependency; a syntactically valid rule is not sufficient evidence that vector
labels combine as intended.

The current file contains 14 alerts in four groups. Site monitoring must add
disk space and I/O latency, host CPU/softnet/NIC drops, certificate and token
rotation, clock sync, APN lease headroom, external end-to-end probes, and
capacity-specific thresholds. A rule file is not an on-call process: route
warning and critical notifications, attach runbooks, and rehearse ownership.

The operator endurance harness is deployment-specific and is deliberately not
stored in this public repository. Build it around the isolated service and
dataplane runners under `deploy/benchmark/`. It must refuse an active
subscriber path, use a dedicated address plan, perform complete four-component
sessions with bidirectional payloads, sample RSS, restart one component at
each fault interval, check association recovery, wait for authoritative stores
to return to zero, and fail on application/socket drops, tracking drift,
cleanup leakage, or excess RSS growth.

Each run should preserve JSONL cycle, memory, and fault evidence plus summaries
in ms and SHA-256 checksums in a private evidence directory. Review latency
tails and RSS trend across the full run rather than relying only on the final
pass marker. The harness reports traffic integrity, not a Mbps saturation
rating; use an independent physical generator/validator for capacity.

The production gate is one uninterrupted 24–72 hour run on the exact signed
candidate and intended host/kernel configuration, with alerts actively
scraped and at least process-restart, abrupt-crash, log-rotation, disk-pressure,
and host-restart recovery rehearsals. A short rehearsal proves the harness but
does not satisfy endurance qualification.

Before the endurance run, prove real Sxa and Sxb accounting on the exact
candidate. In an isolated configuration, lower the reporting threshold from
1 GiB to one byte, send one bidirectional subscriber flow, require durable
acknowledgement on both PFCP interfaces with no retry, gap, or conflict, and
restore both configuration files byte-for-byte. This is an accounting delivery
test, not charging-system certification.
