# Private deployment boundary

This repository contains the reusable LTE CUPS implementation, lab
configuration, tests, release tooling, and operator documentation. It does not
contain any operator's live deployment overlay.

The following material must remain outside version control:

- production and canary addresses, routes, interface names, and firewall rules;
- subscriber identifiers, packet captures, raw logs, and unredacted telemetry;
- credentials, certificates, private keys, and management access details;
- site-specific systemd units and rollback scripts; and
- raw benchmark output that identifies a host or network topology.

Use the configurations in `configs/` and units in `deploy/systemd/` as generic
starting points. Keep real values in a separately secured operations
repository or configuration-management system. Before a public release, scan
the complete Git history as well as the checked-out files.
