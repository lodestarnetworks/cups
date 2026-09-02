# PGW-C dedicated-bearer policy API

The PGW-C policy API is the protected authoritative interface for creating,
updating, reading, and deleting LTE dedicated-bearer policy. It is suitable for
a Lodestar policy controller or a PCRF/Gx adapter. It is deliberately separate
from the public, read-only SGW dashboard and does not implement Diameter Gx.

Policy state is committed to the PGW-C authority journal before success is
returned. The stable policy ID in each URL is persisted with the bearer, so a
controller may retry an uncertain request without creating a second bearer.
Concurrent operations for one session are serialized and global in-flight and
request-body limits are enforced.

## Secure configuration

For a local controller, bind only to loopback:

```yaml
policy_listen: 127.0.0.1:8182
policy_auth_token_file: /var/lib/sgw-next/pgw-policy-token
policy_max_body_bytes: 65536
policy_max_in_flight: 64
```

The token file must be a regular, non-symlink file readable by the PGW-C
service identity, contain 32–512 non-whitespace bytes, and grant no group or
other permissions. Secrets in YAML and command-line flags are unsupported.

A non-loopback `10.0.0.0/8` listener additionally requires all three mTLS
fields. PGW-C accepts TLS 1.3 clients only and verifies them against the
configured controller CA:

```yaml
policy_listen: 10.200.60.3:8182
policy_auth_token_file: /var/lib/sgw-next/pgw-policy-token
policy_tls_cert_file: /etc/sgw-next/policy-server.crt
policy_tls_key_file: /etc/sgw-next/policy-server.key
policy_tls_client_ca_file: /etc/sgw-next/policy-client-ca.crt
```

Network policy must admit only the designated policy-controller addresses.
Bearer-token authentication remains mandatory when mTLS is enabled. Rotate a
token with a coordinated PGW-C restart; never log it or place it in a support
bundle.

## Resource model

Every request requires `Authorization: Bearer <token>` and returns JSON except
successful deletes (`204 No Content`). Available routes are:

- `GET /v1/healthz`
- `GET /v1/sessions?apn=ims&ue_ipv4=10.46.0.2`
- `GET /v1/sessions/{sessionID}/policies`
- `GET /v1/sessions/{sessionID}/policies/{policyID}`
- `PUT /v1/sessions/{sessionID}/policies/{policyID}`
- `DELETE /v1/sessions/{sessionID}/policies/{policyID}`

Policy IDs are 1–64 URL-safe ASCII characters, begin with an alphanumeric
character, and may subsequently contain letters, digits, `_`, `.`, `:`, or
`-`. They must remain stable for the lifetime of the intended policy.

An IMS media example is:

```json
{
  "ebi": 6,
  "qci": 1,
  "arp": 2,
  "preemptionCapable": true,
  "preemptionVulnerable": false,
  "uplinkMbrBps": 8000000,
  "downlinkMbrBps": 12000000,
  "uplinkGbrBps": 3000000,
  "downlinkGbrBps": 4000000,
  "tft": {
    "filters": [
      {
        "id": 1,
        "direction": "bidirectional",
        "precedence": 10,
        "protocol": 17,
        "localPort": {"from": 5004, "to": 5004},
        "remotePort": {"from": 5005, "to": 5005}
      }
    ]
  }
}
```

Bitrates are exact bits per second and must be whole kbps. API responses also
show MBR values in Mbps for operators. GBR cannot exceed MBR. A TFT contains
1–15 filters and must classify both uplink and downlink, either with separate
filters or a bidirectional filter. The supported safe subset is IPv4 prefixes,
TCP/UDP/SCTP protocol and port ranges, and type-of-service value/mask.

The first PUT returns `201` with `result: created`. An identical retry returns
`200` with `result: unchanged`; a QoS-only change returns `200` with
`result: updated`. A TFT change is intentionally non-atomic and returns `409`:
delete and recreate the policy so the controller owns the interruption. Delete
is idempotent and returns `204` even when the policy is already absent.

## Operations and observability

Audit events contain operation, policy ID, session ID, and result, but no token
or subscriber identity. PGW-C exports request, authentication-failure,
validation, outcome, saturation, and in-flight metrics under
`lodestar_pgw_policy_api_*`. Install the rules in
`deploy/prometheus/lodestar-cups-alerts.yaml` and alert on authentication
bursts, failed bearer procedures, and any saturation.

This API supplies the missing production-shaped policy boundary but is not by
itself a PCRF, subscriber-policy database, admission controller, or lawful
intercept system. Those remain separate deployment responsibilities.
