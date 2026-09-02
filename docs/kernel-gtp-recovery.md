# PGW-U kernel-GTP crash recovery

The kernel backend requires a persistent ownership record for every configured
GTP interface:

```yaml
datapath_backend: kernel-gtp
tunnel_name: lspgwu0
kernel_gtp_ownership_file: /var/lib/sgw-next/pgw-u.kernel-owner
state_file: /var/lib/sgw-next/pgw-u.wal
```

Create the parent directory before starting PGW-U. It must be owned by the
service UID and must not be writable by group or others. The owner file is
created with mode `0600`, must remain a regular single-link file owned by the
service UID, and must not be a symbolic link. Keep it across clean restarts.
Do not share or copy one owner file between PGW-U instances.

The record contains a version, interface name, and random 256-bit identity.
PGW-U holds an exclusive non-blocking lock for its full lifetime. A second
process using the same identity fails with `ErrOwnerActive`. `SIGKILL` releases
the lock but leaves the identity available for recovery.

The identity is written into the Linux interface alias and both nftables rule
markers. On restart, PGW-U verifies the complete interface type/name/alias and
the table family, chain, set, and two rule markers before deleting anything.
A missing, malformed, mismatched, or administrator-modified object makes
startup fail closed with `ErrNotOwned`; it is preserved for investigation.

Successful recovery emits a structured warning and exposes:

```text
lodestar_pgwu_kernel_recoveries_total{resource="gtp_link"}
lodestar_pgwu_kernel_recoveries_total{resource="peer_firewall"}
```

Automated integration tests use a real child-process `SIGKILL`, then verify
recovery and clean teardown. Separate cases prove that an active owner, a
different durable token, a same-named dummy interface, and an unowned nftables
table are never reclaimed. These tests have passed in disposable network
namespaces on both a development virtual machine and the bare-metal test host.
