# Release qualification and provenance

Release candidates are built without Docker. The qualification entry point
runs Go vet, normal and race-enabled tests, all component and benchmark config
checks, the pinned dashboard verification, shell syntax checks, and a
reproducible double build. When pnpm is unavailable on an offline build host,
the dashboard gate accepts only an installed dependency tree whose embedded
lockfile is byte-identical to `pnpm-lock.yaml`:

```sh
GO=/opt/sgw-next/toolchains/go/bin/go \
PNPM=/opt/sgw-next/toolchains/node/bin/pnpm \
deploy/release/qualify-source.sh 0.1.0-rc.2
```

`build-release.sh` compiles each of SGW-C, SGW-U, PGW-C, and PGW-U twice with
CGO disabled, `-trimpath`, no VCS stamping, and no Go build ID. A byte mismatch
fails the build. It then emits:

- four static Linux amd64 binaries;
- full-file `SHA256SUMS` and an archive digest;
- source-tree SHA-256 and machine-readable build provenance;
- a deterministic CycloneDX 1.6 SBOM derived from binary build metadata;
- a deterministic tar archive with normalized owner, group, ordering, and
  timestamp.

Unsigned candidates receive an adjacent `.UNSIGNED` marker and are not
approved for production publication. For a signed candidate, provide an
owner-only Ed25519 private key and require signing:

```sh
SIGNING_KEY=/secure/offline/lodestar-release-ed25519.pem \
REQUIRE_SIGNATURE=1 \
GO=/opt/sgw-next/toolchains/go/bin/go \
deploy/release/build-release.sh 0.1.0-rc.2
```

Keep production signing material outside the source tree and build host where
possible. Never store it on a gateway.

Verify an extracted artifact before staging it:

```sh
VERIFY_PUBLIC_KEY=/etc/lodestar-release.pub \
VERIFY_ARCHIVE=/srv/releases/lodestar-cups-0.1.0-linux-amd64.tar.gz \
REQUIRE_SIGNATURE=1 \
deploy/release/verify-release.sh \
  /srv/releases/lodestar-cups-0.1.0-linux-amd64
```

The verifier checks all file digests, binary versions, SBOM and provenance
shape, signature, symbolic links, setuid/setgid bits, and world-writable files.

Stage each version in a new immutable directory and retain the last qualified
version. Validate all four `--check-config` commands against the staged
binaries before atomically changing a `current` link while the isolated target
is stopped. Start in dependency order, run
service/restart/crash/policy/usage-report/soak
gates, and roll back by stopping the target and restoring the prior link.
Never overwrite an existing release directory or reuse a WAL with incompatible
identity-bearing configuration.

Production publication remains blocked until the candidate is signed, the
24–72 hour soak passes, live UE/VoLTE interoperability is approved, and the
site-specific routing, firewall, failover, and recovery runbooks are exercised.
