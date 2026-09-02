# Security policy

Lodestar CUPS is pre-release engineering software. Do not expose its UDP listeners or
management API to an untrusted network and do not use it to carry production
subscriber traffic.

## Current defaults

- The lab API binds to loopback.
- CORS is limited to the local dashboard origins.
- HTTP responses disable caching and framing.
- Protocol parsers validate minimum size, version, declared length, and nested
  extension boundaries before returning payload bytes.
- State stores clone input/output and commit validated updates atomically.
- Dashboard events use masked or opaque subscriber references.

## Required before production

- mTLS and RBAC for all management listeners;
- per-source UDP rate limits and bounded worker queues;
- complete grouped-IE nesting and allocation budgets;
- cryptographically random non-zero TEID/SEID allocation with collision checks;
- privilege separation and narrowly scoped Linux capabilities;
- persistent-state integrity, rollback protection, and secure deletion policy;
- fuzzing, dependency scanning, SBOM, signed releases, and external review.

## Reporting

No public security contact exists while the project remains local. Before the
first public release, create a private reporting address and publish supported
versions and response targets here. Do not open a public issue containing an
unpatched vulnerability or subscriber data.
