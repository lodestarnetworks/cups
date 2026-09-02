package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadPGWCStrictYAML(t *testing.T) {
	path := writeConfig(t, "pgw-c.yaml", `
management_listen: 10.200.60.1:8180
s5_listen: 10.200.10.1:2123
s5_advertise: 10.200.10.1
allowed_sgw: [10.200.10.2]
pfcp_listen: 10.200.20.1:8805
pfcp_advertise: 10.200.20.1
pfcp_remote: 10.200.20.2:8805
pgwu_user_ip: 10.200.30.1
pgwu_qci1_user_ip: 10.200.30.2
apn: lodestartest
ue_pool_prefix: 10.90.0.0/24
ue_gateway: 10.90.0.1
dns_ipv4: [10.200.40.1, 10.200.40.2]
ipv4_link_mtu: 1400
apn_ambr_uplink_bps: 1000000000
apn_ambr_downlink_bps: 2000000000
subscriber_salt: this-is-a-test-salt
state_file: /var/lib/sgw-next/pgw-c.wal
admission_drain_file: /run/lodestar/pgw-c.drain
`)
	value, err := LoadPGWC(path)
	if err != nil {
		t.Fatal(err)
	}
	if value.MaxSessions != 1_000_000 || value.PGWUQCI1UserIP != "10.200.30.2" || value.APNAMBRDownlinkBPS != 2_000_000_000 || value.RetransmitTimeout != "1s" ||
		value.StateFile != "/var/lib/sgw-next/pgw-c.wal" || value.StateWALMaxBytes != 1<<30 || value.ReconcileWorkers != 64 ||
		value.AdmissionDrainFile != "/run/lodestar/pgw-c.drain" || value.AdmissionPollInterval != "250ms" {
		t.Fatalf("unexpected defaults or bitrate units: %#v", value)
	}

	unknown := writeConfig(t, "unknown.yaml", strings.ReplaceAll(mustRead(t, path), "apn: lodestartest", "apn: lodestartest\nunknown_key: true"))
	if _, err := LoadPGWC(unknown); err == nil {
		t.Fatal("strict YAML accepted an unknown key")
	}
}

func TestLoadSGWCControlState(t *testing.T) {
	path := writeConfig(t, "sgw-c.yaml", `
management_listen: 10.200.60.1:8080
allowed_origins: [http://localhost:3000]
sgwu_metrics_url: http://10.200.60.2:8081
s11_listen: 10.200.10.1:2123
s11_advertise: 10.200.10.1
allowed_mme: [10.200.10.2]
s5_listen: 10.200.20.1:2123
s5_advertise: 10.200.20.1
pgw_control: 10.200.20.2:2123
pgw_routes:
  - apn: IMS
    address: 10.200.20.3:2123
pfcp_listen: 10.200.30.1:8805
pfcp_advertise: 10.200.30.1
pfcp_remote: 10.200.30.2:8805
sgwu_access_ip: 10.200.40.1
sgwu_core_ip: 10.200.50.1
subscriber_salt: this-is-a-test-salt
state_file: /var/lib/sgw-next/sgw-c.wal
admission_drain_file: /run/lodestar/sgw-c.drain
admission_poll_interval: 100ms
`)
	value, err := LoadSGWC(path)
	if err != nil {
		t.Fatal(err)
	}
	if value.StateFile != "/var/lib/sgw-next/sgw-c.wal" || value.StateWALMaxBytes != 1<<30 || value.ReconcileWorkers != 64 ||
		len(value.PGWRoutes) != 1 || value.PGWRoutes[0].APN != "ims" || value.PGWRoutes[0].Address != "10.200.20.3:2123" ||
		value.AdmissionDrainFile != "/run/lodestar/sgw-c.drain" || value.AdmissionPollInterval != "100ms" {
		t.Fatalf("SGW-C state defaults = %#v", value)
	}

	duplicate := writeConfig(t, "sgw-c-duplicate-route.yaml", strings.ReplaceAll(mustRead(t, path),
		"    address: 10.200.20.3:2123", "    address: 10.200.20.3:2123\n  - apn: ims\n    address: 10.200.20.4:2123"))
	if _, err := LoadSGWC(duplicate); err == nil || !strings.Contains(err.Error(), "duplicates") {
		t.Fatalf("duplicate APN route error = %v", err)
	}

	invalidAPN := writeConfig(t, "sgw-c-invalid-route-apn.yaml", strings.ReplaceAll(mustRead(t, path), "apn: IMS", "apn: bad_apn"))
	if _, err := LoadSGWC(invalidAPN); err == nil || !strings.Contains(err.Error(), "APN labels") {
		t.Fatalf("invalid APN route error = %v", err)
	}

	publicRoute := writeConfig(t, "sgw-c-public-route.yaml", strings.ReplaceAll(mustRead(t, path), "10.200.20.3:2123", "192.0.2.3:2123"))
	if _, err := LoadSGWC(publicRoute); err == nil || !strings.Contains(err.Error(), "Lodestar 10.0.0.0/8") {
		t.Fatalf("public PGW route error = %v", err)
	}
}

func TestNormalizeReconcileWorkers(t *testing.T) {
	workers := 0
	if err := normalizeReconcileWorkers(&workers); err != nil || workers != 64 {
		t.Fatalf("default reconciliation workers = %d, %v", workers, err)
	}
	for _, invalid := range []int{-1, 1025} {
		workers = invalid
		if err := normalizeReconcileWorkers(&workers); err == nil {
			t.Fatalf("accepted reconciliation worker count %d", invalid)
		}
	}
}

func TestNormalizeControlStateRejectsUnsafeConfiguration(t *testing.T) {
	tests := []struct {
		name string
		path string
		max  int64
	}{
		{name: "relative", path: "state/control.wal"},
		{name: "root", path: "/"},
		{name: "size without path", max: 1 << 20},
		{name: "undersized", path: "/var/lib/sgw-next/control.wal", max: (1 << 20) - 1},
		{name: "negative", path: "/var/lib/sgw-next/control.wal", max: -1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path, max := test.path, test.max
			if err := normalizeControlState(&path, &max); err == nil {
				t.Fatalf("normalizeControlState(%q, %d) succeeded", test.path, test.max)
			}
		})
	}
}

func TestNormalizeAdmissionDrainRejectsUnsafeConfiguration(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		interval string
	}{
		{name: "interval-without-file", interval: "250ms"},
		{name: "relative", path: "run/sgw-c.drain"},
		{name: "root", path: "/"},
		{name: "too-fast", path: "/run/lodestar/sgw-c.drain", interval: "1ms"},
		{name: "too-slow", path: "/run/lodestar/sgw-c.drain", interval: "1m"},
		{name: "invalid-duration", path: "/run/lodestar/sgw-c.drain", interval: "soon"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path, interval := test.path, test.interval
			if err := normalizeAdmissionDrain(&path, &interval); err == nil {
				t.Fatalf("normalizeAdmissionDrain(%q, %q) succeeded", test.path, test.interval)
			}
		})
	}
}

func TestLoadSGWUValidatesTCXFastPath(t *testing.T) {
	base := `
management_listen: 10.200.60.2:8081
pfcp_listen: 10.200.30.2:8805
pfcp_advertise: 10.200.30.2
allowed_sgwc: [10.200.30.1]
access_gtpu_listen: 10.200.40.1:2152
allowed_access_peers: [10.200.40.2]
core_gtpu_listen: 10.200.50.1:2152
allowed_core_peers: [10.200.50.2]
fast_path:
  mode: tcx
  access_interface: sgwaccess0
  core_interface: sgwcore0
  access_neighbours:
    - ip: 10.200.40.2
      mac: 02:00:00:00:40:02
  core_neighbours:
    - ip: 10.200.50.2
      mac: 02:00:00:00:50:02
`
	path := writeConfig(t, "sgw-u-tcx.yaml", base)
	value, err := LoadSGWU(path)
	if err != nil {
		t.Fatal(err)
	}
	if value.FastPath.Mode != "tcx" || value.FastPath.MaxRules != 4_000_000 || value.GTPUBatchSize != 64 {
		t.Fatalf("unexpected TCX defaults %#v", value.FastPath)
	}

	mismatch := writeConfig(t, "sgw-u-tcx-mismatch.yaml", strings.ReplaceAll(base, "ip: 10.200.40.2", "ip: 10.200.40.3"))
	if _, err := LoadSGWU(mismatch); err == nil || !strings.Contains(err.Error(), "not an allowed peer") {
		t.Fatalf("mismatched fast-path peer error = %v", err)
	}
	badMAC := writeConfig(t, "sgw-u-tcx-mac.yaml", strings.ReplaceAll(base, "02:00:00:00:40:02", "ff:ff:ff:ff:ff:ff"))
	if _, err := LoadSGWU(badMAC); err == nil || !strings.Contains(err.Error(), "neighbour MAC") {
		t.Fatalf("invalid fast-path MAC error = %v", err)
	}
	sameInterface := writeConfig(t, "sgw-u-tcx-interface.yaml", strings.ReplaceAll(base, "core_interface: sgwcore0", "core_interface: sgwaccess0"))
	if _, err := LoadSGWU(sameInterface); err == nil || !strings.Contains(err.Error(), "must differ") {
		t.Fatalf("same fast-path interface error = %v", err)
	}
}

func TestLoadPGWURejectsDevelopmentBackendInProduction(t *testing.T) {
	path := writeConfig(t, "pgw-u.yaml", `
management_listen: 10.200.60.2:8181
apn: lodestartest
pfcp_listen: 10.200.20.2:8805
pfcp_advertise: 10.200.20.2
allowed_pgwc: [10.200.20.1]
s5_gtpu_listen: 10.200.30.1:2152
allowed_sgwu: [10.200.30.2]
tunnel_name: lspgwu0
datapath_backend: userspace-development
production: true
`)
	if _, err := LoadPGWU(path); err == nil || !strings.Contains(err.Error(), "disabled in production") {
		t.Fatalf("production userspace backend error = %v", err)
	}
}

func TestLoadPGWUAcceptsKernelGTPForIsolatedTesting(t *testing.T) {
	path := writeConfig(t, "pgw-u-kernel.yaml", `
management_listen: 10.200.60.2:8181
apn: lodestartest
pfcp_listen: 10.200.20.2:8805
pfcp_advertise: 10.200.20.2
allowed_pgwc: [10.200.20.1]
s5_gtpu_listen: 10.200.30.1:2152
allowed_sgwu: [10.200.30.2]
tunnel_name: lspgwu0
datapath_backend: kernel-gtp
production: false
ue_pool_prefix: 10.201.0.0/16
ue_gateway: 10.201.0.1
kernel_gtp_ownership_file: /var/lib/sgw-next/pgw-u.kernel-owner
`)
	value, err := LoadPGWU(path)
	if err != nil {
		t.Fatal(err)
	}
	if value.KernelGTPHashSize != 131_072 || value.KernelGTPMTU != 1_400 {
		t.Fatalf("kernel defaults = %#v", value)
	}
	missingOwner := writeConfig(t, "pgw-u-kernel-missing-owner.yaml", strings.ReplaceAll(mustRead(t, path), "kernel_gtp_ownership_file: /var/lib/sgw-next/pgw-u.kernel-owner\n", ""))
	if _, err := LoadPGWU(missingOwner); err == nil || !strings.Contains(err.Error(), "kernel_gtp_ownership_file") {
		t.Fatalf("missing kernel ownership file error = %v", err)
	}
	relativeOwner := writeConfig(t, "pgw-u-kernel-relative-owner.yaml", strings.ReplaceAll(mustRead(t, path), "/var/lib/sgw-next/pgw-u.kernel-owner", "pgw-u.kernel-owner"))
	if _, err := LoadPGWU(relativeOwner); err == nil || !strings.Contains(err.Error(), "absolute file path") {
		t.Fatalf("relative kernel ownership file error = %v", err)
	}

	production := writeConfig(t, "pgw-u-kernel-production.yaml", strings.ReplaceAll(mustRead(t, path), "production: false", "production: true"))
	if _, err := LoadPGWU(production); err == nil || !strings.Contains(err.Error(), "QCI 1") {
		t.Fatalf("kernel production gate error = %v", err)
	}
	productionConfig := strings.ReplaceAll(mustRead(t, path), "production: false", "production: true") + `qci1_s5_gtpu_listen: 10.200.30.3:2152
qci1_tunnel_name: lspgwu1
qci1_kernel_gtp_ownership_file: /var/lib/sgw-next/pgw-u-qci1.kernel-owner
state_file: /var/lib/sgw-next/pgw-u.wal
`
	productionReady := writeConfig(t, "pgw-u-kernel-production-ready.yaml", productionConfig)
	ready, err := LoadPGWU(productionReady)
	if err != nil {
		t.Fatal(err)
	}
	if ready.MaxPolicyFilters != 8_000_000 || ready.StateWALMaxBytes != 1<<30 ||
		ready.QCI1RouteTable != 21_521 || ready.QCI1RulePriority != 10_510 ||
		ready.QCI1FirewallMark != 0x4c51_0000 || ready.QCI1FirewallMask != 0xffff_0000 {
		t.Fatalf("production kernel defaults = %#v", ready)
	}
	partialQCI1 := writeConfig(t, "pgw-u-kernel-partial-qci1.yaml", mustRead(t, path)+"qci1_tunnel_name: lspgwu1\n")
	if _, err := LoadPGWU(partialQCI1); err == nil || !strings.Contains(err.Error(), "configured together") {
		t.Fatalf("partial QCI 1 config error = %v", err)
	}
}

func TestLoadPGWUAcceptsDisjointMultiAPNPools(t *testing.T) {
	base := `
management_listen: 10.200.60.2:8181
pfcp_listen: 10.200.20.2:8805
pfcp_advertise: 10.200.20.2
allowed_pgwc: [10.200.20.1]
s5_gtpu_listen: 10.200.30.1:2152
allowed_sgwu: [10.200.30.2]
tunnel_name: lspgwu0
datapath_backend: kernel-gtp
production: false
ue_pools:
  - apn: internet
    ue_pool_prefix: 10.45.0.0/16
    ue_gateway: 10.45.0.1
  - apn: IMS
    ue_pool_prefix: 10.46.0.0/16
    ue_gateway: 10.46.0.1
kernel_gtp_ownership_file: /var/lib/sgw-next/pgw-u.kernel-owner
`
	path := writeConfig(t, "pgw-u-multi-pool.yaml", base)
	value, err := LoadPGWU(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(value.UEPools) != 2 || value.UEPools[0].APN != "internet" || value.UEPools[1].APN != "ims" ||
		value.UEPools[1].UEPoolPrefix != "10.46.0.0/16" {
		t.Fatalf("normalized PGW-U pools = %#v", value.UEPools)
	}
	overlapConfig := strings.ReplaceAll(base, "10.46.0.0/16", "10.45.1.0/24")
	overlapConfig = strings.ReplaceAll(overlapConfig, "10.46.0.1", "10.45.1.1")
	overlap := writeConfig(t, "pgw-u-overlap.yaml", overlapConfig)
	if _, err := LoadPGWU(overlap); err == nil || !strings.Contains(err.Error(), "overlaps") {
		t.Fatalf("overlapping pool error = %v", err)
	}
	legacyMix := writeConfig(t, "pgw-u-legacy-mix.yaml", base+"apn: legacy\nue_pool_prefix: 10.47.0.0/16\nue_gateway: 10.47.0.1\n")
	if _, err := LoadPGWU(legacyMix); err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("mixed legacy/multi-pool error = %v", err)
	}
}

func TestLoadPGWUValidatesDurableStatePath(t *testing.T) {
	base := `
management_listen: 10.200.60.2:8181
apn: lodestartest
pfcp_listen: 10.200.20.2:8805
pfcp_advertise: 10.200.20.2
allowed_pgwc: [10.200.20.1]
s5_gtpu_listen: 10.200.30.1:2152
allowed_sgwu: [10.200.30.2]
tunnel_name: lspgwu0
datapath_backend: kernel-gtp
production: false
ue_pool_prefix: 10.201.0.0/16
ue_gateway: 10.201.0.1
kernel_gtp_ownership_file: /var/lib/sgw-next/pgw-u.kernel-owner
state_file: /var/lib/sgw-next/pgw-u.wal
`
	path := writeConfig(t, "pgw-u-state.yaml", base)
	value, err := LoadPGWU(path)
	if err != nil {
		t.Fatal(err)
	}
	if value.StateWALMaxBytes != 1<<30 || value.StateFile != "/var/lib/sgw-next/pgw-u.wal" {
		t.Fatalf("state defaults = %#v", value)
	}
	relative := writeConfig(t, "pgw-u-relative-state.yaml", strings.ReplaceAll(base, "/var/lib/sgw-next/pgw-u.wal", "state/pgw-u.wal"))
	if _, err := LoadPGWU(relative); err == nil || !strings.Contains(err.Error(), "absolute file path") {
		t.Fatalf("relative state path error = %v", err)
	}
}

func TestLoadPGWCRejectsNonLodestarAddressing(t *testing.T) {
	path := writeConfig(t, "bad.yaml", `
management_listen: 10.200.60.1:8180
s5_listen: 10.200.10.1:2123
s5_advertise: 172.16.0.1
allowed_sgw: [10.200.10.2]
pfcp_listen: 10.200.20.1:8805
pfcp_advertise: 10.200.20.1
pfcp_remote: 10.200.20.2:8805
pgwu_user_ip: 10.200.30.1
apn: lodestartest
ue_pool_prefix: 10.90.0.0/24
ue_gateway: 10.90.0.1
dns_ipv4: [10.200.40.1, 10.200.40.2]
apn_ambr_uplink_bps: 1000000000
apn_ambr_downlink_bps: 2000000000
subscriber_salt: this-is-a-test-salt
`)
	if _, err := LoadPGWC(path); err == nil || !strings.Contains(err.Error(), "10.0.0.0/8") {
		t.Fatalf("non-10.x addressing error = %v", err)
	}
}

func TestLoadPGWCPolicyEndpointSecurity(t *testing.T) {
	base := `
management_listen: 10.200.60.1:8180
s5_listen: 10.200.10.1:2123
s5_advertise: 10.200.10.1
allowed_sgw: [10.200.10.2]
pfcp_listen: 10.200.20.1:8805
pfcp_advertise: 10.200.20.1
pfcp_remote: 10.200.20.2:8805
pgwu_user_ip: 10.200.30.1
apn: lodestartest
ue_pool_prefix: 10.90.0.0/24
ue_gateway: 10.90.0.1
dns_ipv4: [10.200.40.1, 10.200.40.2]
apn_ambr_uplink_bps: 1000000000
apn_ambr_downlink_bps: 2000000000
subscriber_salt: this-is-a-test-salt
`
	loopback := writeConfig(t, "pgw-c-policy-loopback.yaml", base+`
policy_listen: 127.0.0.1:8182
policy_auth_token_file: /run/credentials/pgw-c/policy-token
`)
	value, err := LoadPGWC(loopback)
	if err != nil {
		t.Fatal(err)
	}
	if value.PolicyMaxBodyBytes != 64<<10 || value.PolicyMaxInFlight != 64 {
		t.Fatalf("policy defaults = body %d in-flight %d", value.PolicyMaxBodyBytes, value.PolicyMaxInFlight)
	}

	remoteWithoutTLS := writeConfig(t, "pgw-c-policy-plaintext.yaml", strings.ReplaceAll(mustRead(t, loopback), "127.0.0.1:8182", "10.200.60.1:8182"))
	if _, err := LoadPGWC(remoteWithoutTLS); err == nil || !strings.Contains(err.Error(), "mutual TLS") {
		t.Fatalf("remote plaintext policy error = %v", err)
	}
	remoteMTLS := writeConfig(t, "pgw-c-policy-mtls.yaml", mustRead(t, remoteWithoutTLS)+`
policy_tls_cert_file: /etc/lodestar/policy-server.crt
policy_tls_key_file: /run/credentials/pgw-c/policy-server.key
policy_tls_client_ca_file: /etc/lodestar/policy-client-ca.crt
`)
	if _, err := LoadPGWC(remoteMTLS); err != nil {
		t.Fatalf("remote mTLS policy config: %v", err)
	}
	partialTLS := writeConfig(t, "pgw-c-policy-partial-tls.yaml", mustRead(t, loopback)+`
policy_tls_cert_file: /etc/lodestar/policy-server.crt
`)
	if _, err := LoadPGWC(partialTLS); err == nil || !strings.Contains(err.Error(), "configured together") {
		t.Fatalf("partial policy TLS error = %v", err)
	}
	missingListen := writeConfig(t, "pgw-c-policy-missing-listen.yaml", base+`
policy_auth_token_file: /run/credentials/pgw-c/policy-token
`)
	if _, err := LoadPGWC(missingListen); err == nil || !strings.Contains(err.Error(), "require policy_listen") {
		t.Fatalf("missing policy listen error = %v", err)
	}
}

func TestPGWConfigsRejectReserved3GPPEnterpriseID(t *testing.T) {
	pgwc := writeConfig(t, "pgw-c-reserved-enterprise.yaml", `
management_listen: 10.200.60.1:8180
s5_listen: 10.200.10.1:2123
s5_advertise: 10.200.10.1
allowed_sgw: [10.200.10.2]
pfcp_listen: 10.200.20.1:8805
pfcp_advertise: 10.200.20.1
pfcp_remote: 10.200.20.2:8805
pfcp_enterprise_id: 10415
pgwu_user_ip: 10.200.30.1
apn: lodestartest
ue_pool_prefix: 10.90.0.0/24
ue_gateway: 10.90.0.1
dns_ipv4: [10.200.40.1, 10.200.40.2]
apn_ambr_uplink_bps: 1000000000
apn_ambr_downlink_bps: 2000000000
subscriber_salt: this-is-a-test-salt
`)
	if _, err := LoadPGWC(pgwc); err == nil || !strings.Contains(err.Error(), "reserved for 3GPP") {
		t.Fatalf("PGW-C reserved enterprise ID error = %v", err)
	}

	pgwu := writeConfig(t, "pgw-u-reserved-enterprise.yaml", `
management_listen: 10.200.60.2:8181
apn: lodestartest
pfcp_listen: 10.200.20.2:8805
pfcp_advertise: 10.200.20.2
pfcp_enterprise_id: 10415
allowed_pgwc: [10.200.20.1]
s5_gtpu_listen: 10.200.30.1:2152
allowed_sgwu: [10.200.30.2]
tunnel_name: lspgwu0
datapath_backend: userspace-development
`)
	if _, err := LoadPGWU(pgwu); err == nil || !strings.Contains(err.Error(), "reserved for 3GPP") {
		t.Fatalf("PGW-U reserved enterprise ID error = %v", err)
	}
}

func writeConfig(t *testing.T, name, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(strings.TrimSpace(contents)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(contents)
}
