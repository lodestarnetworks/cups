# SGW-C and PGW-C durable recovery

SGW-C and PGW-C can use a local, checksummed transition journal as their
authoritative session store. In durable mode every accepted create, update,
reconciliation change, and delete is appended and `fsync`ed before the
in-memory indexes change or GTPv2-C acknowledgement is sent.

Each control plane also keeps a separate `<state_file>.peers` journal for the
last accepted GTPv2 Recovery counter from every canonical peer endpoint. SGW-C
tracks S11 MME and S5 PGW peers; PGW-C tracks S5 SGW peers. Keeping this state
outside the subscriber journal preserves its record format and rollback
compatibility.

This closes the single-host process-crash/restart gap. It is not cross-site
active/standby replication: the journal and its `flock` fence are local to one
host. Multi-site failover still requires a replicated consensus/fencing layer
and remains a release gate.

## Configuration

Use a local filesystem owned by the service account. Do not place these files
on NFS or another filesystem whose `flock`, atomic rename, and directory
`fsync` semantics have not been independently validated.

```yaml
# SGW-C
state_file: /var/lib/sgw-next/sgw-c.wal
state_wal_max_bytes: 4294967296
reconcile_workers: 64
```

```yaml
# PGW-C
state_file: /var/lib/sgw-next/pgw-c.wal
state_wal_max_bytes: 4294967296
reconcile_workers: 64
```

The parent directory must be owned by the process UID and not writable by its
group or others. Journals and their adjacent `.lock` files must be single-link
regular files with mode `0600` or stricter. Symlinks and hard-linked files are
rejected. The shipped systemd units create `/var/lib/sgw-next` with mode
`0700`.

The 1 GiB parser default is suitable for labs, but deployments sized toward
the one-million-session software limit should start with at least 4 GiB and
validate this against their bearer mix. Compaction temporarily needs space for
both the old journal and a complete live snapshot. Alert well before either
the configured byte limit or filesystem capacity is reached.

## Startup and fencing sequence

1. Open and exclusively lock the stable `.lock` file and current journal
   inode. A second local owner fails immediately.
2. Verify the component/configuration identity digest, file header, every
   frame length, CRC32C checksum, record version, revision sequence, immutable
   identity, and all recovered lookup-index uniqueness constraints.
3. SGW-C rebuilds its session indexes. PGW-C also restores every exact UE IPv4
   lease and validates it against the configured pool. Both processes restore
   and validate their bounded peer-recovery maps.
4. Only after local validation succeeds, append and `fsync` the new ownership
   epoch and advance the GTPv2 recovery counter.
5. Associate to SGW-U/PGW-U, replay the complete authoritative PFCP state with
   a bounded worker pool, and complete reconciliation so stale user-plane
   state is removed.
6. Start serving S11/S5-C traffic.

Malformed or configuration-mismatched state fails closed before a new startup
epoch is committed. A partial final frame caused by power loss is truncated to
the last fully checksummed boundary and reported in telemetry. Corruption in a
complete frame is never silently skipped.

## Runtime commit and failure rules

- Session stores call the journal before mutating any in-memory index.
- A write or `fsync` failure poisons that store. Later mutations fail rather
  than allowing memory and disk to diverge.
- Exact PFCP replay is idempotent. An unchanged UP-SEID/rule graph does not
  advance a session revision or append a duplicate WAL transition.
- A changed UP-SEID returned after a genuine user-plane restart is committed
  durably before the recovered session is advertised as ready.
- Startup replay reserves every recovered TEID and SEID before new allocation.
- A changed MME counter makes SGW-C delete the matching PGW-C/U and SGW-U
  contexts before local state and the new counter are committed. A changed
  SGW-C counter makes PGW-C delete matching PGW-U and local PDN state first.
- A downstream timeout, rejection, or durable peer-counter failure withholds
  the triggering GTP request. Retransmission retries the cleanup. GTP Context
  Not Found and PFCP Session Not Found are accepted only for deletion, making
  a partially completed cleanup safe to resume after a process restart.
- Relayed procedures never copy another node's Recovery IE across an
  interface. SGW-C stamps its own counter on S11 and S5 requests; PGW-C stamps
  its own counter on S5 bearer requests.

## Atomic compaction

Each control journal keeps a canonical encoded snapshot of live sessions.
Compaction is considered when the file is at least half its configured limit
and at least one quarter of that limit is reclaimable, or when the next append
would otherwise exceed the limit.

The replacement is written in the same directory with a fresh random name,
fully checksummed, `fsync`ed, locked, atomically renamed over the old journal,
and followed by a directory `fsync`. The stable `.lock` remains held across
the rename; the old and replacement journal inodes are also locked so an older
binary cannot become a concurrent owner during a rolling upgrade. A process
death can therefore expose either the complete old journal or the complete
new snapshot, never a half-installed mixture. Safe mode-0600 temporary files
left by a pre-rename `SIGKILL` are removed on the next fenced startup; unsafe
lookalike paths fail closed.

If the live snapshot plus one transition cannot fit inside
`state_wal_max_bytes`, compaction cannot help and the store fails closed with a
capacity error. This is why sizing and free-space alerts are mandatory.

## Metrics

SGW-C exports these through its SGW-only dashboard/API and Prometheus endpoint:

- `sgw_next_sgwc_control_state_durable`
- `sgw_next_sgwc_control_state_wal_bytes`
- `sgw_next_sgwc_control_state_wal_records_total`
- `sgw_next_sgwc_control_state_starts_total`
- `sgw_next_sgwc_control_state_compactions_total`
- `sgw_next_sgwc_control_state_recovered_sessions`
- `sgw_next_sgwc_control_state_tail_recovered`
- `sgw_next_sgwc_recovery_counter`

PGW-C exports equivalent `lodestar_pgw_control_state_*` metrics plus
`lodestar_pgw_control_recovery_counter`,
`lodestar_pgw_peer_restarts_total`, and
`lodestar_pgw_peer_restart_purge_failures_total`. SGW-C exports
`sgw_next_sgwc_peer_restart_purge_failures_total` for the same fail-closed
condition. SGW-C also exports
`sgw_next_sgwc_delete_session_context_not_found_reconciliations_total` when a
Delete Session finishes local SGW-C/U cleanup after PGW-C has already removed
its half of the context. The bundled critical alert covers either control
plane.

## Current validation evidence

On the bare-metal test host, a full isolated 10,000-session SGW-C → PGW-C →
Sxa/Sxb → SGW-U/PGW-U test recovered and reconciled every session in
1,373.646 ms with
64 replay workers, then modified and deleted every session with zero failures,
retransmissions, worker drops, socket drops, stale purges, or leaks.

A second run deliberately limited both control journals to 16 MiB. It forced
five SGW-C and two PGW-C atomic compactions while executing the same 10,000
session lifecycle and controlled restart. Restart took 1,638.655 ms and all
counters remained clean. Separate process-fault tests issued `SIGKILL` at
three delays around a 16 MiB compaction attempt and always recovered one
complete authoritative version.

A 100,000-session durable restart restored all four session stores and every
UE lease in 16,330.046 ms. The full all-in-one harness peaked at about 1.53 GiB
RSS and finished 300,000 LTE procedures with zero retransmissions, timeouts,
worker/socket drops, stale purges, or leaks. The raw benchmark artifacts remain
under `/var/tmp` on the test host and are not deployment inputs.

The in-process four-component LTE test on the bare-metal test host establishes
a bearer across SGW-C, SGW-U, PGW-C, and PGW-U, changes the MME Recovery
counter, and verifies that all four stores reach zero before Echo Response.
Separate fault tests prove that PGW and PFCP timeouts withhold the response,
retries complete, and already-deleted GTP/PFCP contexts are handled
idempotently. The reciprocal PGW-C test proves that an SGW-C counter change
does not advance until PGW-U, the PDN journal, and the IPv4 lease are clean.

## Remaining resilience gate

Local durability must not be described as site failover. Production
active/standby still needs authenticated state replication, a quorum-backed
lease or equivalent external fence, monotonic term/epoch handling, promotion
and demotion procedures, split-brain tests, and an operator-visible failover
state. Until that exists, only one control-plane site may own a given APN and
session shard.
