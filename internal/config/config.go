// Package config loads strict YAML configuration for the CUPS processes. JSON
// remains readable during migration so the running SGW can be upgraded without
// an unsafe flag day.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type SGWU struct {
	ManagementListen   string            `json:"managementListen" yaml:"management_listen"`
	DebugListen        string            `json:"debugListen" yaml:"debug_listen"`
	AllowedOrigins     []string          `json:"allowedOrigins" yaml:"allowed_origins"`
	PFCPListen         string            `json:"pfcpListen" yaml:"pfcp_listen"`
	PFCPAdvertise      string            `json:"pfcpAdvertise" yaml:"pfcp_advertise"`
	PFCPEnterpriseID   uint16            `json:"pfcpEnterpriseId" yaml:"pfcp_enterprise_id"`
	AllowedSGWC        []string          `json:"allowedSgwc" yaml:"allowed_sgwc"`
	AccessGTPUListen   string            `json:"accessGtpuListen" yaml:"access_gtpu_listen"`
	AllowedAccessPeers []string          `json:"allowedAccessPeers" yaml:"allowed_access_peers"`
	CoreGTPUListen     string            `json:"coreGtpuListen" yaml:"core_gtpu_listen"`
	AllowedCorePeers   []string          `json:"allowedCorePeers" yaml:"allowed_core_peers"`
	SocketBufferBytes  int               `json:"socketBufferBytes" yaml:"socket_buffer_bytes"`
	GTPUBatchSize      int               `json:"gtpuBatchSize" yaml:"gtpu_batch_size"`
	QERBurstDuration   string            `json:"qerBurstDuration" yaml:"qer_burst_duration"`
	ReportQueueSize    int               `json:"downlinkReportQueueSize" yaml:"downlink_report_queue_size"`
	ReportSuppression  string            `json:"downlinkReportSuppression" yaml:"downlink_report_suppression"`
	ReportTimeout      string            `json:"downlinkReportTimeout" yaml:"downlink_report_timeout"`
	AssociationTimeout string            `json:"associationTimeout" yaml:"association_timeout"`
	GraceWindow        string            `json:"associationGraceWindow" yaml:"association_grace_window"`
	RetransmitTimeout  string            `json:"retransmitTimeout" yaml:"retransmit_timeout"`
	MaxRetransmits     int               `json:"maxRetransmits" yaml:"max_retransmits"`
	MaxSessions        int               `json:"maxSessions" yaml:"max_sessions"`
	DownlinkBuffering  []SGWUBufferClass `json:"downlinkBuffering" yaml:"downlink_buffering"`
	FastPath           SGWUFastPath      `json:"fastPath" yaml:"fast_path"`
}

type SGWUBufferClass struct {
	QCI                 uint8  `json:"qci" yaml:"qci"`
	MaxPackets          int    `json:"maxPackets" yaml:"max_packets"`
	MaxBytes            int64  `json:"maxBytes" yaml:"max_bytes"`
	MaxPacketsPerBearer int    `json:"maxPacketsPerBearer" yaml:"max_packets_per_bearer"`
	HoldTime            string `json:"holdTime" yaml:"hold_time"`
}

type SGWUFastPath struct {
	Mode             string                  `json:"mode" yaml:"mode"`
	AccessInterface  string                  `json:"accessInterface" yaml:"access_interface"`
	CoreInterface    string                  `json:"coreInterface" yaml:"core_interface"`
	MaxRules         int                     `json:"maxRules" yaml:"max_rules"`
	AccessNeighbours []SGWUFastPathNeighbour `json:"accessNeighbours" yaml:"access_neighbours"`
	CoreNeighbours   []SGWUFastPathNeighbour `json:"coreNeighbours" yaml:"core_neighbours"`
}

type SGWUFastPathNeighbour struct {
	IP  string `json:"ip" yaml:"ip"`
	MAC string `json:"mac" yaml:"mac"`
}

type SGWC struct {
	ManagementListen          string         `json:"managementListen" yaml:"management_listen"`
	AllowedOrigins            []string       `json:"allowedOrigins" yaml:"allowed_origins"`
	SGWUMetricsURL            string         `json:"sgwuMetricsUrl" yaml:"sgwu_metrics_url"`
	S11Listen                 string         `json:"s11Listen" yaml:"s11_listen"`
	S11Advertise              string         `json:"s11Advertise" yaml:"s11_advertise"`
	AllowedMME                []string       `json:"allowedMme" yaml:"allowed_mme"`
	S5Listen                  string         `json:"s5Listen" yaml:"s5_listen"`
	S5Advertise               string         `json:"s5Advertise" yaml:"s5_advertise"`
	PGWControl                string         `json:"pgwControl" yaml:"pgw_control"`
	PGWRoutes                 []SGWCPGWRoute `json:"pgwRoutes" yaml:"pgw_routes"`
	PFCPListen                string         `json:"pfcpListen" yaml:"pfcp_listen"`
	PFCPAdvertise             string         `json:"pfcpAdvertise" yaml:"pfcp_advertise"`
	PFCPRemote                string         `json:"pfcpRemote" yaml:"pfcp_remote"`
	PFCPEnterpriseID          uint16         `json:"pfcpEnterpriseId" yaml:"pfcp_enterprise_id"`
	DownlinkNotificationDelay string         `json:"downlinkNotificationDelay" yaml:"downlink_notification_delay"`
	UsageReportingThreshold   uint64         `json:"usageReportingThresholdBytes" yaml:"usage_reporting_threshold_bytes"`
	SGWUAccessIP              string         `json:"sgwuAccessIp" yaml:"sgwu_access_ip"`
	SGWUCoreIP                string         `json:"sgwuCoreIp" yaml:"sgwu_core_ip"`
	RecoveryCounter           uint8          `json:"recoveryCounter" yaml:"recovery_counter"`
	ProcedureTimeout          string         `json:"procedureTimeout" yaml:"procedure_timeout"`
	HeartbeatInterval         string         `json:"heartbeatInterval" yaml:"heartbeat_interval"`
	RetransmitTimeout         string         `json:"retransmitTimeout" yaml:"retransmit_timeout"`
	MaxRetransmits            int            `json:"maxRetransmits" yaml:"max_retransmits"`
	ReconcileWorkers          int            `json:"reconcileWorkers" yaml:"reconcile_workers"`
	SubscriberSalt            string         `json:"subscriberSalt" yaml:"subscriber_salt"`
	SubscriberSaltFile        string         `json:"subscriberSaltFile" yaml:"subscriber_salt_file"`
	MaxSessions               int            `json:"maxSessions" yaml:"max_sessions"`
	StateFile                 string         `json:"stateFile" yaml:"state_file"`
	StateWALMaxBytes          int64          `json:"stateWalMaxBytes" yaml:"state_wal_max_bytes"`
	AdmissionDrainFile        string         `json:"admissionDrainFile" yaml:"admission_drain_file"`
	AdmissionPollInterval     string         `json:"admissionPollInterval" yaml:"admission_poll_interval"`
}

// SGWCPGWRoute selects a PGW-C for one exact APN. PGWControl remains the
// mandatory default for APNs without an explicit route.
type SGWCPGWRoute struct {
	APN     string `json:"apn" yaml:"apn"`
	Address string `json:"address" yaml:"address"`
}

type PGWC struct {
	ManagementListen        string           `yaml:"management_listen"`
	PolicyListen            string           `yaml:"policy_listen"`
	PolicyAuthTokenFile     string           `yaml:"policy_auth_token_file"`
	PolicyTLSCertFile       string           `yaml:"policy_tls_cert_file"`
	PolicyTLSKeyFile        string           `yaml:"policy_tls_key_file"`
	PolicyTLSClientCAFile   string           `yaml:"policy_tls_client_ca_file"`
	PolicyMaxBodyBytes      int64            `yaml:"policy_max_body_bytes"`
	PolicyMaxInFlight       int              `yaml:"policy_max_in_flight"`
	S5Listen                string           `yaml:"s5_listen"`
	S5Advertise             string           `yaml:"s5_advertise"`
	AllowedSGW              []string         `yaml:"allowed_sgw"`
	PFCPListen              string           `yaml:"pfcp_listen"`
	PFCPAdvertise           string           `yaml:"pfcp_advertise"`
	PFCPRemote              string           `yaml:"pfcp_remote"`
	PFCPEnterpriseID        uint16           `yaml:"pfcp_enterprise_id"`
	PGWUUserIP              string           `yaml:"pgwu_user_ip"`
	PGWUQCI1UserIP          string           `yaml:"pgwu_qci1_user_ip"`
	APN                     string           `yaml:"apn"`
	UEPoolPrefix            string           `yaml:"ue_pool_prefix"`
	UEGateway               string           `yaml:"ue_gateway"`
	DNSIPv4                 []string         `yaml:"dns_ipv4"`
	IPv4LinkMTU             uint16           `yaml:"ipv4_link_mtu"`
	APNAMBRUplinkBPS        uint64           `yaml:"apn_ambr_uplink_bps"`
	APNAMBRDownlinkBPS      uint64           `yaml:"apn_ambr_downlink_bps"`
	PCSCFIPv4               []string         `yaml:"pcscf_ipv4"`
	APNProfiles             []PGWCAPNProfile `yaml:"apn_profiles"`
	UsageReportingThreshold uint64           `yaml:"usage_reporting_threshold_bytes"`
	RecoveryCounter         uint8            `yaml:"recovery_counter"`
	ProcedureTimeout        string           `yaml:"procedure_timeout"`
	HeartbeatInterval       string           `yaml:"heartbeat_interval"`
	RetransmitTimeout       string           `yaml:"retransmit_timeout"`
	MaxRetransmits          int              `yaml:"max_retransmits"`
	ReconcileWorkers        int              `yaml:"reconcile_workers"`
	SubscriberSalt          string           `yaml:"subscriber_salt"`
	SubscriberSaltFile      string           `yaml:"subscriber_salt_file"`
	MaxSessions             int              `yaml:"max_sessions"`
	StateFile               string           `yaml:"state_file"`
	StateWALMaxBytes        int64            `yaml:"state_wal_max_bytes"`
	AdmissionDrainFile      string           `yaml:"admission_drain_file"`
	AdmissionPollInterval   string           `yaml:"admission_poll_interval"`
}

// PGWCAPNProfile owns all address allocation and UE-facing policy for one
// exact APN. Keeping the pool in the profile prevents a lease or PCO response
// from one APN being accidentally reused by another.
type PGWCAPNProfile struct {
	APN                string   `json:"apn" yaml:"apn"`
	UEPoolPrefix       string   `json:"uePoolPrefix" yaml:"ue_pool_prefix"`
	UEGateway          string   `json:"ueGateway" yaml:"ue_gateway"`
	DNSIPv4            []string `json:"dnsIPv4" yaml:"dns_ipv4"`
	PCSCFIPv4          []string `json:"pcscfIPv4" yaml:"pcscf_ipv4"`
	IPv4LinkMTU        uint16   `json:"ipv4LinkMtu" yaml:"ipv4_link_mtu"`
	APNAMBRUplinkBPS   uint64   `json:"apnAmbrUplinkBps" yaml:"apn_ambr_uplink_bps"`
	APNAMBRDownlinkBPS uint64   `json:"apnAmbrDownlinkBps" yaml:"apn_ambr_downlink_bps"`
}

type PGWU struct {
	ManagementListen       string       `yaml:"management_listen"`
	DebugListen            string       `yaml:"debug_listen"`
	APN                    string       `yaml:"apn"`
	PFCPListen             string       `yaml:"pfcp_listen"`
	PFCPAdvertise          string       `yaml:"pfcp_advertise"`
	PFCPEnterpriseID       uint16       `yaml:"pfcp_enterprise_id"`
	AllowedPGWC            []string     `yaml:"allowed_pgwc"`
	S5GTPUListen           string       `yaml:"s5_gtpu_listen"`
	AllowedSGWU            []string     `yaml:"allowed_sgwu"`
	TunnelName             string       `yaml:"tunnel_name"`
	QCI1S5GTPUListen       string       `yaml:"qci1_s5_gtpu_listen"`
	QCI1TunnelName         string       `yaml:"qci1_tunnel_name"`
	DatapathBackend        string       `yaml:"datapath_backend"`
	Production             bool         `yaml:"production"`
	UEPoolPrefix           string       `yaml:"ue_pool_prefix"`
	UEGateway              string       `yaml:"ue_gateway"`
	UEPools                []PGWUUEPool `yaml:"ue_pools"`
	KernelGTPHashSize      uint32       `yaml:"kernel_gtp_hash_size"`
	KernelGTPMTU           uint32       `yaml:"kernel_gtp_mtu"`
	KernelGTPOwnerFile     string       `yaml:"kernel_gtp_ownership_file"`
	QCI1KernelGTPOwnerFile string       `yaml:"qci1_kernel_gtp_ownership_file"`
	QCI1RouteTable         uint32       `yaml:"qci1_route_table"`
	QCI1RulePriority       uint32       `yaml:"qci1_rule_priority"`
	QCI1FirewallMark       uint32       `yaml:"qci1_firewall_mark"`
	QCI1FirewallMask       uint32       `yaml:"qci1_firewall_mask"`
	MaxPolicyFilters       int          `yaml:"max_policy_filters"`
	SocketBufferBytes      int          `yaml:"socket_buffer_bytes"`
	MaxPacketSize          int          `yaml:"max_packet_size"`
	QERBurstDuration       string       `yaml:"qer_burst_duration"`
	AssociationTimeout     string       `yaml:"association_timeout"`
	GraceWindow            string       `yaml:"association_grace_window"`
	RetransmitTimeout      string       `yaml:"retransmit_timeout"`
	MaxRetransmits         int          `yaml:"max_retransmits"`
	MaxSessions            int          `yaml:"max_sessions"`
	StateFile              string       `yaml:"state_file"`
	StateWALMaxBytes       int64        `yaml:"state_wal_max_bytes"`
}

// PGWUUEPool declares one UE range routed through the shared PGW-U GTP
// devices. The APN label is retained for validation and operator metrics;
// PFCP and the kernel dataplane route sessions by UE address.
type PGWUUEPool struct {
	APN          string `json:"apn" yaml:"apn"`
	UEPoolPrefix string `json:"uePoolPrefix" yaml:"ue_pool_prefix"`
	UEGateway    string `json:"ueGateway" yaml:"ue_gateway"`
}

func LoadSGWU(path string) (SGWU, error) {
	var value SGWU
	if err := load(path, &value); err != nil {
		return SGWU{}, err
	}
	if value.ManagementListen == "" || value.PFCPListen == "" || value.PFCPAdvertise == "" ||
		value.AccessGTPUListen == "" || value.CoreGTPUListen == "" || len(value.AllowedSGWC) == 0 ||
		len(value.AllowedAccessPeers) == 0 || len(value.AllowedCorePeers) == 0 {
		return SGWU{}, errors.New("config: SGW-U management, PFCP, GTP-U, and allowed SGW-C fields are required")
	}
	if value.SocketBufferBytes < 0 {
		return SGWU{}, errors.New("config: SGW-U socket buffer bytes cannot be negative")
	}
	if value.GTPUBatchSize < 0 || value.GTPUBatchSize > 1024 {
		return SGWU{}, errors.New("config: SGW-U GTP-U batch size must be between 1 and 1024 when set")
	}
	if value.GTPUBatchSize == 0 {
		value.GTPUBatchSize = 64
	}
	if value.DebugListen == "" {
		value.DebugListen = "127.0.0.1:6060"
	}
	if err := requireLoopbackAddrPort(value.DebugListen, "debug_listen"); err != nil {
		return SGWU{}, err
	}
	if value.QERBurstDuration == "" {
		value.QERBurstDuration = "100ms"
	}
	qerBurst, err := Duration(value.QERBurstDuration, "qer_burst_duration")
	if err != nil {
		return SGWU{}, err
	}
	if qerBurst < time.Millisecond || qerBurst > time.Second {
		return SGWU{}, errors.New("config: SGW-U qer_burst_duration must be between 1ms and 1s")
	}
	if value.PFCPEnterpriseID == 10415 {
		return SGWU{}, errors.New("config: PFCP enterprise ID 10415 is reserved for 3GPP")
	}
	if value.SocketBufferBytes == 0 {
		value.SocketBufferBytes = 16 * 1024 * 1024
	}
	if value.ReportQueueSize < 0 {
		return SGWU{}, errors.New("config: SGW-U downlink report queue size cannot be negative")
	}
	if value.MaxSessions < 0 {
		return SGWU{}, errors.New("config: SGW-U maximum sessions cannot be negative")
	}
	if value.MaxSessions == 0 {
		value.MaxSessions = 1_000_000
	}
	if value.FastPath.Mode == "" {
		value.FastPath.Mode = "off"
	}
	switch value.FastPath.Mode {
	case "off":
		if value.FastPath.AccessInterface != "" || value.FastPath.CoreInterface != "" || value.FastPath.MaxRules != 0 || len(value.FastPath.AccessNeighbours) != 0 || len(value.FastPath.CoreNeighbours) != 0 {
			return SGWU{}, errors.New("config: SGW-U fast_path fields require mode: tcx")
		}
	case "tcx":
		if err := validateInterfaceName(value.FastPath.AccessInterface); err != nil {
			return SGWU{}, fmt.Errorf("config: SGW-U fast_path access interface: %w", err)
		}
		if err := validateInterfaceName(value.FastPath.CoreInterface); err != nil {
			return SGWU{}, fmt.Errorf("config: SGW-U fast_path core interface: %w", err)
		}
		if value.FastPath.AccessInterface == value.FastPath.CoreInterface {
			return SGWU{}, errors.New("config: SGW-U fast_path access and core interfaces must differ")
		}
		if value.FastPath.MaxRules == 0 {
			value.FastPath.MaxRules = 4_000_000
		}
		if value.FastPath.MaxRules < 4 || value.FastPath.MaxRules > 8_000_000 {
			return SGWU{}, errors.New("config: SGW-U fast_path max_rules must be between 4 and 8000000")
		}
		if err := validateFastPathNeighbours(value.FastPath.AccessNeighbours, "access"); err != nil {
			return SGWU{}, err
		}
		if err := validateFastPathNeighbours(value.FastPath.CoreNeighbours, "core"); err != nil {
			return SGWU{}, err
		}
		if err := validateFastPathPeerSet(value.FastPath.AccessNeighbours, value.AllowedAccessPeers, "access"); err != nil {
			return SGWU{}, err
		}
		if err := validateFastPathPeerSet(value.FastPath.CoreNeighbours, value.AllowedCorePeers, "core"); err != nil {
			return SGWU{}, err
		}
	default:
		return SGWU{}, fmt.Errorf("config: unsupported SGW-U fast_path mode %q", value.FastPath.Mode)
	}
	if len(value.DownlinkBuffering) == 0 {
		value.DownlinkBuffering = []SGWUBufferClass{
			{QCI: 0, MaxPackets: 65_536, MaxBytes: 64 * 1024 * 1024, MaxPacketsPerBearer: 32, HoldTime: "5s"},
			{QCI: 5, MaxPackets: 16_384, MaxBytes: 16 * 1024 * 1024, MaxPacketsPerBearer: 64, HoldTime: "10s"},
		}
	}
	seenQCI := make(map[uint8]struct{}, len(value.DownlinkBuffering))
	for index, class := range value.DownlinkBuffering {
		if class.QCI == 255 {
			return SGWU{}, fmt.Errorf("config: invalid SGW-U downlink buffer QCI at index %d", index)
		}
		if _, exists := seenQCI[class.QCI]; exists {
			return SGWU{}, fmt.Errorf("config: duplicate SGW-U downlink buffer QCI %d", class.QCI)
		}
		seenQCI[class.QCI] = struct{}{}
		if class.MaxPackets <= 0 || class.MaxPackets > 1_000_000 || class.MaxBytes <= 0 || class.MaxBytes > 1<<30 || class.MaxPacketsPerBearer <= 0 || class.MaxPacketsPerBearer > class.MaxPackets {
			return SGWU{}, fmt.Errorf("config: invalid SGW-U downlink buffer limits at index %d", index)
		}
		hold, err := Duration(class.HoldTime, fmt.Sprintf("downlink_buffering[%d].hold_time", index))
		if err != nil {
			return SGWU{}, err
		}
		if hold < 50*time.Millisecond || hold > 10*time.Minute {
			return SGWU{}, fmt.Errorf("config: SGW-U downlink buffer hold time at index %d must be 50ms..10m", index)
		}
	}
	if _, exists := seenQCI[0]; !exists {
		return SGWU{}, errors.New("config: SGW-U downlink buffering requires a qci: 0 default class")
	}
	if value.ReportQueueSize == 0 {
		value.ReportQueueSize = 1024
	}
	if value.ReportSuppression == "" {
		value.ReportSuppression = "5s"
	}
	if value.ReportTimeout == "" {
		value.ReportTimeout = "5s"
	}
	if value.AssociationTimeout == "" {
		value.AssociationTimeout = "15s"
	}
	if value.GraceWindow == "" {
		value.GraceWindow = "120s"
	}
	if value.RetransmitTimeout == "" {
		value.RetransmitTimeout = "1s"
	}
	if value.MaxRetransmits == 0 {
		value.MaxRetransmits = 3
	}
	for field, address := range map[string]string{
		"management_listen": value.ManagementListen, "pfcp_listen": value.PFCPListen,
		"access_gtpu_listen": value.AccessGTPUListen, "core_gtpu_listen": value.CoreGTPUListen,
	} {
		if err := requireLodestarAddrPort(address, field); err != nil {
			return SGWU{}, err
		}
	}
	if err := requireLodestarIPv4(value.PFCPAdvertise, "pfcp_advertise"); err != nil {
		return SGWU{}, err
	}
	for field, addresses := range map[string][]string{
		"allowed_sgwc": value.AllowedSGWC, "allowed_access_peers": value.AllowedAccessPeers,
		"allowed_core_peers": value.AllowedCorePeers,
	} {
		if err := requireLodestarAddresses(addresses, field); err != nil {
			return SGWU{}, err
		}
	}
	for field, duration := range map[string]string{
		"downlink_report_suppression": value.ReportSuppression, "downlink_report_timeout": value.ReportTimeout,
		"association_timeout": value.AssociationTimeout, "association_grace_window": value.GraceWindow,
		"retransmit_timeout": value.RetransmitTimeout,
	} {
		if _, err := Duration(duration, field); err != nil {
			return SGWU{}, err
		}
	}
	return value, nil
}

func validateInterfaceName(value string) error {
	if value == "" || len(value) > 15 || strings.ContainsAny(value, "/\x00 \t\r\n") {
		return errors.New("interface name must be 1..15 characters without path or whitespace characters")
	}
	return nil
}

func validateFastPathNeighbours(values []SGWUFastPathNeighbour, side string) error {
	if len(values) == 0 {
		return fmt.Errorf("config: SGW-U fast_path %s_neighbours cannot be empty", side)
	}
	seen := make(map[netip.Addr]struct{}, len(values))
	for index, value := range values {
		ip, err := netip.ParseAddr(value.IP)
		if err != nil || !ip.Is4() || !ip.IsPrivate() {
			return fmt.Errorf("config: invalid SGW-U fast_path %s neighbour IP at index %d", side, index)
		}
		ip = ip.Unmap()
		if _, exists := seen[ip]; exists {
			return fmt.Errorf("config: duplicate SGW-U fast_path %s neighbour %s", side, ip)
		}
		seen[ip] = struct{}{}
		mac, err := net.ParseMAC(value.MAC)
		if err != nil || len(mac) != 6 || mac[0]&1 != 0 || isZeroMAC(mac) {
			return fmt.Errorf("config: invalid SGW-U fast_path %s neighbour MAC at index %d", side, index)
		}
	}
	return nil
}

func validateFastPathPeerSet(neighbours []SGWUFastPathNeighbour, allowed []string, side string) error {
	if len(neighbours) != len(allowed) {
		return fmt.Errorf("config: SGW-U fast_path %s neighbours must exactly match allowed peers", side)
	}
	wanted := make(map[netip.Addr]struct{}, len(allowed))
	for index, value := range allowed {
		ip, err := netip.ParseAddr(value)
		if err != nil || !ip.Is4() {
			return fmt.Errorf("config: invalid SGW-U allowed %s peer at index %d", side, index)
		}
		wanted[ip.Unmap()] = struct{}{}
	}
	for _, value := range neighbours {
		ip, _ := netip.ParseAddr(value.IP)
		if _, exists := wanted[ip.Unmap()]; !exists {
			return fmt.Errorf("config: SGW-U fast_path %s neighbour %s is not an allowed peer", side, value.IP)
		}
	}
	return nil
}

func isZeroMAC(value net.HardwareAddr) bool {
	for _, current := range value {
		if current != 0 {
			return false
		}
	}
	return true
}

func LoadSGWC(path string) (SGWC, error) {
	var value SGWC
	if err := load(path, &value); err != nil {
		return SGWC{}, err
	}
	if value.ManagementListen == "" || value.SGWUMetricsURL == "" || value.S11Listen == "" || value.S11Advertise == "" ||
		value.S5Listen == "" || value.S5Advertise == "" || value.PGWControl == "" || value.PFCPListen == "" ||
		value.PFCPAdvertise == "" || value.PFCPRemote == "" || value.SGWUAccessIP == "" || value.SGWUCoreIP == "" ||
		len(value.AllowedMME) == 0 || (value.SubscriberSalt == "" && value.SubscriberSaltFile == "") {
		return SGWC{}, errors.New("config: SGW-C management, S11, S5, PFCP, SGW-U, MME, metrics, and subscriber salt fields are required")
	}
	if value.SubscriberSalt == "" {
		contents, err := os.ReadFile(value.SubscriberSaltFile)
		if err != nil {
			return SGWC{}, fmt.Errorf("config: read subscriber salt file: %w", err)
		}
		value.SubscriberSalt = strings.TrimSpace(string(contents))
	}
	if len(value.SubscriberSalt) < 16 {
		return SGWC{}, errors.New("config: subscriber salt must contain at least 16 characters")
	}
	if value.MaxSessions < 0 {
		return SGWC{}, errors.New("config: SGW-C maximum sessions cannot be negative")
	}
	if value.MaxSessions == 0 {
		value.MaxSessions = 1_000_000
	}
	if value.PFCPEnterpriseID == 10415 {
		return SGWC{}, errors.New("config: PFCP enterprise ID 10415 is reserved for 3GPP")
	}
	if value.DownlinkNotificationDelay == "" {
		value.DownlinkNotificationDelay = "0s"
	}
	if value.UsageReportingThreshold == 0 {
		value.UsageReportingThreshold = 1 << 30
	}
	delay, err := NonNegativeDuration(value.DownlinkNotificationDelay, "downlink_notification_delay")
	if err != nil {
		return SGWC{}, err
	}
	if delay < 0 || delay > 12_750*time.Millisecond || delay%(50*time.Millisecond) != 0 {
		return SGWC{}, errors.New("config: downlink_notification_delay must be 0..12750ms in 50ms units")
	}
	if err := normalizeControlState(&value.StateFile, &value.StateWALMaxBytes); err != nil {
		return SGWC{}, err
	}
	if err := normalizeAdmissionDrain(&value.AdmissionDrainFile, &value.AdmissionPollInterval); err != nil {
		return SGWC{}, err
	}
	if value.ProcedureTimeout == "" {
		value.ProcedureTimeout = "5s"
	}
	if value.HeartbeatInterval == "" {
		value.HeartbeatInterval = "5s"
	}
	if value.RetransmitTimeout == "" {
		value.RetransmitTimeout = "1s"
	}
	if value.MaxRetransmits == 0 {
		value.MaxRetransmits = 3
	}
	if err := normalizeReconcileWorkers(&value.ReconcileWorkers); err != nil {
		return SGWC{}, err
	}
	for field, address := range map[string]string{
		"management_listen": value.ManagementListen, "s11_listen": value.S11Listen,
		"s5_listen": value.S5Listen, "pgw_control": value.PGWControl,
		"pfcp_listen": value.PFCPListen, "pfcp_remote": value.PFCPRemote,
	} {
		if err := requireLodestarAddrPort(address, field); err != nil {
			return SGWC{}, err
		}
	}
	seenAPNs := make(map[string]struct{}, len(value.PGWRoutes))
	for index := range value.PGWRoutes {
		route := &value.PGWRoutes[index]
		normalizedAPN, err := normalizeAPNRoute(route.APN)
		if err != nil {
			return SGWC{}, fmt.Errorf("config: pgw_routes[%d].apn: %w", index, err)
		}
		if _, duplicate := seenAPNs[normalizedAPN]; duplicate {
			return SGWC{}, fmt.Errorf("config: pgw_routes[%d].apn duplicates %q", index, normalizedAPN)
		}
		field := fmt.Sprintf("pgw_routes[%d].address", index)
		if err := requireLodestarAddrPort(route.Address, field); err != nil {
			return SGWC{}, err
		}
		address, _ := AddrPort(route.Address, field)
		route.APN = normalizedAPN
		route.Address = address.String()
		seenAPNs[normalizedAPN] = struct{}{}
	}
	for field, address := range map[string]string{
		"s11_advertise": value.S11Advertise, "s5_advertise": value.S5Advertise,
		"pfcp_advertise": value.PFCPAdvertise, "sgwu_access_ip": value.SGWUAccessIP,
		"sgwu_core_ip": value.SGWUCoreIP,
	} {
		if err := requireLodestarIPv4(address, field); err != nil {
			return SGWC{}, err
		}
	}
	if err := requireLodestarAddresses(value.AllowedMME, "allowed_mme"); err != nil {
		return SGWC{}, err
	}
	if err := requireLodestarURL(value.SGWUMetricsURL, "sgwu_metrics_url"); err != nil {
		return SGWC{}, err
	}
	for field, duration := range map[string]string{
		"procedure_timeout": value.ProcedureTimeout, "heartbeat_interval": value.HeartbeatInterval,
		"retransmit_timeout": value.RetransmitTimeout,
	} {
		if _, err := Duration(duration, field); err != nil {
			return SGWC{}, err
		}
	}
	return value, nil
}

func normalizeAPNRoute(value string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if len(normalized) == 0 || len(normalized) > 100 {
		return "", errors.New("APN must contain between 1 and 100 ASCII characters")
	}
	for _, label := range strings.Split(normalized, ".") {
		if len(label) == 0 || len(label) > 63 {
			return "", errors.New("APN labels must contain between 1 and 63 characters")
		}
		for index := 0; index < len(label); index++ {
			current := label[index]
			alphaNumeric := current >= 'a' && current <= 'z' || current >= '0' && current <= '9'
			if !alphaNumeric && (current != '-' || index == 0 || index == len(label)-1) {
				return "", errors.New("APN labels may contain only letters, digits, and interior hyphens")
			}
		}
	}
	return normalized, nil
}

func normalizePGWCAPNProfiles(value *PGWC) error {
	legacyConfigured := value.APN != "" || value.UEPoolPrefix != "" || value.UEGateway != "" ||
		len(value.DNSIPv4) != 0 || len(value.PCSCFIPv4) != 0 || value.IPv4LinkMTU != 0 ||
		value.APNAMBRUplinkBPS != 0 || value.APNAMBRDownlinkBPS != 0
	if len(value.APNProfiles) != 0 && legacyConfigured {
		return errors.New("config: apn_profiles cannot be combined with legacy top-level APN, pool, PCO, or APN-AMBR fields")
	}
	if len(value.APNProfiles) == 0 {
		if value.APN == "" || value.UEPoolPrefix == "" || value.UEGateway == "" || len(value.DNSIPv4) != 2 ||
			value.APNAMBRUplinkBPS == 0 || value.APNAMBRDownlinkBPS == 0 {
			return errors.New("config: PGW-C requires apn_profiles or one legacy APN, pool, two DNS servers, and APN-AMBR profile")
		}
		value.APNProfiles = []PGWCAPNProfile{{
			APN: value.APN, UEPoolPrefix: value.UEPoolPrefix, UEGateway: value.UEGateway,
			DNSIPv4: append([]string(nil), value.DNSIPv4...), PCSCFIPv4: append([]string(nil), value.PCSCFIPv4...),
			IPv4LinkMTU: value.IPv4LinkMTU, APNAMBRUplinkBPS: value.APNAMBRUplinkBPS,
			APNAMBRDownlinkBPS: value.APNAMBRDownlinkBPS,
		}}
	}
	seen := make(map[string]struct{}, len(value.APNProfiles))
	prefixes := make([]netip.Prefix, 0, len(value.APNProfiles))
	const maxAMBRBPS = uint64(^uint32(0)) * 1000
	for index := range value.APNProfiles {
		profile := &value.APNProfiles[index]
		apn, err := normalizeAPNRoute(profile.APN)
		if err != nil {
			return fmt.Errorf("config: apn_profiles[%d].apn: %w", index, err)
		}
		if _, exists := seen[apn]; exists {
			return fmt.Errorf("config: apn_profiles[%d] duplicates APN %q", index, apn)
		}
		seen[apn] = struct{}{}
		profile.APN = apn
		if len(profile.DNSIPv4) != 2 {
			return fmt.Errorf("config: apn_profiles[%d] requires exactly two IPv4 DNS servers", index)
		}
		if len(profile.PCSCFIPv4) > 2 {
			return fmt.Errorf("config: apn_profiles[%d] supports at most two IPv4 P-CSCF addresses", index)
		}
		if profile.IPv4LinkMTU == 0 {
			profile.IPv4LinkMTU = 1400
		}
		if profile.IPv4LinkMTU < 1280 || profile.IPv4LinkMTU > 1500 {
			return fmt.Errorf("config: apn_profiles[%d].ipv4_link_mtu must be between 1280 and 1500 bytes", index)
		}
		if profile.APNAMBRUplinkBPS == 0 || profile.APNAMBRDownlinkBPS == 0 ||
			profile.APNAMBRUplinkBPS%1000 != 0 || profile.APNAMBRDownlinkBPS%1000 != 0 ||
			profile.APNAMBRUplinkBPS > maxAMBRBPS || profile.APNAMBRDownlinkBPS > maxAMBRBPS {
			return fmt.Errorf("config: apn_profiles[%d] APN-AMBR must be non-zero whole kilobits per second expressed in bits per second", index)
		}
		prefix, err := Prefix(profile.UEPoolPrefix, fmt.Sprintf("apn_profiles[%d].ue_pool_prefix", index))
		if err != nil {
			return err
		}
		if !prefix.Addr().Is4() || prefix.Bits() < 8 || prefix.Bits() > 30 || !netip.MustParsePrefix("10.0.0.0/8").Contains(prefix.Addr()) {
			return fmt.Errorf("config: apn_profiles[%d].ue_pool_prefix must be an IPv4 /8../30 inside Lodestar 10.0.0.0/8 addressing", index)
		}
		gateway, err := Addr(profile.UEGateway, fmt.Sprintf("apn_profiles[%d].ue_gateway", index))
		if err != nil {
			return err
		}
		if !prefix.Contains(gateway) {
			return fmt.Errorf("config: apn_profiles[%d].ue_gateway must be inside its UE pool", index)
		}
		for otherIndex, other := range prefixes {
			if prefix.Contains(other.Addr()) || other.Contains(prefix.Addr()) {
				return fmt.Errorf("config: apn_profiles[%d].ue_pool_prefix overlaps profile %d", index, otherIndex)
			}
		}
		if err := requireLodestarAddresses(profile.DNSIPv4, fmt.Sprintf("apn_profiles[%d].dns_ipv4", index)); err != nil {
			return err
		}
		if err := requireLodestarAddresses(profile.PCSCFIPv4, fmt.Sprintf("apn_profiles[%d].pcscf_ipv4", index)); err != nil {
			return err
		}
		profile.UEPoolPrefix = prefix.String()
		profile.UEGateway = gateway.String()
		prefixes = append(prefixes, prefix)
	}
	if legacyConfigured {
		profile := value.APNProfiles[0]
		value.APN, value.UEPoolPrefix, value.UEGateway = profile.APN, profile.UEPoolPrefix, profile.UEGateway
		value.DNSIPv4, value.PCSCFIPv4 = append([]string(nil), profile.DNSIPv4...), append([]string(nil), profile.PCSCFIPv4...)
		value.IPv4LinkMTU = profile.IPv4LinkMTU
	}
	return nil
}

func LoadPGWC(path string) (PGWC, error) {
	var value PGWC
	if err := loadYAML(path, &value); err != nil {
		return PGWC{}, err
	}
	if value.ManagementListen == "" || value.S5Listen == "" || value.S5Advertise == "" || len(value.AllowedSGW) == 0 ||
		value.PFCPListen == "" || value.PFCPAdvertise == "" || value.PFCPRemote == "" || value.PGWUUserIP == "" ||
		(value.SubscriberSalt == "" && value.SubscriberSaltFile == "") {
		return PGWC{}, errors.New("config: PGW-C management, S5, PFCP, PGW-U, and subscriber salt fields are required")
	}
	if err := loadSubscriberSalt(&value.SubscriberSalt, value.SubscriberSaltFile); err != nil {
		return PGWC{}, err
	}
	if value.MaxSessions < 0 {
		return PGWC{}, errors.New("config: PGW-C maximum sessions cannot be negative")
	}
	if value.PFCPEnterpriseID == 10415 {
		return PGWC{}, errors.New("config: PFCP enterprise ID 10415 is reserved for 3GPP")
	}
	if value.MaxSessions == 0 {
		value.MaxSessions = 1_000_000
	}
	if err := normalizeControlState(&value.StateFile, &value.StateWALMaxBytes); err != nil {
		return PGWC{}, err
	}
	if err := normalizeAdmissionDrain(&value.AdmissionDrainFile, &value.AdmissionPollInterval); err != nil {
		return PGWC{}, err
	}
	if value.ProcedureTimeout == "" {
		value.ProcedureTimeout = "5s"
	}
	if value.HeartbeatInterval == "" {
		value.HeartbeatInterval = "5s"
	}
	if value.RetransmitTimeout == "" {
		value.RetransmitTimeout = "1s"
	}
	if value.MaxRetransmits == 0 {
		value.MaxRetransmits = 3
	}
	if err := normalizeReconcileWorkers(&value.ReconcileWorkers); err != nil {
		return PGWC{}, err
	}
	if value.UsageReportingThreshold == 0 {
		value.UsageReportingThreshold = 1 << 30
	}
	if err := normalizePGWCAPNProfiles(&value); err != nil {
		return PGWC{}, err
	}
	if err := normalizePGWCPolicy(&value); err != nil {
		return PGWC{}, err
	}
	if err := requireLodestarAddrPort(value.S5Listen, "s5_listen"); err != nil {
		return PGWC{}, err
	}
	if err := requireLodestarIPv4(value.S5Advertise, "s5_advertise"); err != nil {
		return PGWC{}, err
	}
	if err := requireLodestarAddresses(value.AllowedSGW, "allowed_sgw"); err != nil {
		return PGWC{}, err
	}
	if err := requireLodestarAddrPort(value.PFCPListen, "pfcp_listen"); err != nil {
		return PGWC{}, err
	}
	if err := requireLodestarIPv4(value.PFCPAdvertise, "pfcp_advertise"); err != nil {
		return PGWC{}, err
	}
	if err := requireLodestarAddrPort(value.PFCPRemote, "pfcp_remote"); err != nil {
		return PGWC{}, err
	}
	if err := requireLodestarIPv4(value.PGWUUserIP, "pgwu_user_ip"); err != nil {
		return PGWC{}, err
	}
	if value.PGWUQCI1UserIP != "" {
		if err := requireLodestarIPv4(value.PGWUQCI1UserIP, "pgwu_qci1_user_ip"); err != nil {
			return PGWC{}, err
		}
		defaultUser, _ := Addr(value.PGWUUserIP, "pgwu_user_ip")
		qci1User, _ := Addr(value.PGWUQCI1UserIP, "pgwu_qci1_user_ip")
		if defaultUser == qci1User {
			return PGWC{}, errors.New("config: pgwu_qci1_user_ip must differ from pgwu_user_ip")
		}
	}
	if err := requireLodestarAddrPort(value.ManagementListen, "management_listen"); err != nil {
		return PGWC{}, err
	}
	for field, duration := range map[string]string{
		"procedure_timeout": value.ProcedureTimeout, "heartbeat_interval": value.HeartbeatInterval,
		"retransmit_timeout": value.RetransmitTimeout,
	} {
		if _, err := Duration(duration, field); err != nil {
			return PGWC{}, err
		}
	}
	return value, nil
}

func normalizePGWCPolicy(value *PGWC) error {
	configuredFields := []string{
		value.PolicyAuthTokenFile, value.PolicyTLSCertFile, value.PolicyTLSKeyFile, value.PolicyTLSClientCAFile,
	}
	if strings.TrimSpace(value.PolicyListen) == "" {
		for _, field := range configuredFields {
			if strings.TrimSpace(field) != "" {
				return errors.New("config: PGW-C policy fields require policy_listen")
			}
		}
		if value.PolicyMaxBodyBytes != 0 || value.PolicyMaxInFlight != 0 {
			return errors.New("config: PGW-C policy limits require policy_listen")
		}
		return nil
	}
	listen, err := AddrPort(value.PolicyListen, "policy_listen")
	if err != nil || listen.Port() == 0 || !listen.Addr().Is4() {
		return errors.New("config: policy_listen must be an IPv4 address with a non-zero port")
	}
	if !listen.Addr().IsLoopback() && !netip.MustParsePrefix("10.0.0.0/8").Contains(listen.Addr()) {
		return errors.New("config: policy_listen must use loopback or Lodestar 10.0.0.0/8 addressing")
	}
	if err := normalizeAbsoluteFile(&value.PolicyAuthTokenFile, "policy_auth_token_file", true); err != nil {
		return err
	}
	tlsFields := []*string{&value.PolicyTLSCertFile, &value.PolicyTLSKeyFile, &value.PolicyTLSClientCAFile}
	tlsCount := 0
	for _, field := range tlsFields {
		if strings.TrimSpace(*field) != "" {
			tlsCount++
		}
	}
	if tlsCount != 0 && tlsCount != len(tlsFields) {
		return errors.New("config: policy TLS certificate, key, and client CA files must be configured together")
	}
	if !listen.Addr().IsLoopback() && tlsCount != len(tlsFields) {
		return errors.New("config: non-loopback policy_listen requires mutual TLS")
	}
	for index, field := range tlsFields {
		if tlsCount == 0 {
			break
		}
		name := []string{"policy_tls_cert_file", "policy_tls_key_file", "policy_tls_client_ca_file"}[index]
		if err := normalizeAbsoluteFile(field, name, true); err != nil {
			return err
		}
	}
	if value.PolicyMaxBodyBytes < 0 || value.PolicyMaxBodyBytes > 1<<20 {
		return errors.New("config: policy_max_body_bytes must be between 1024 and 1048576 when set")
	}
	if value.PolicyMaxBodyBytes == 0 {
		value.PolicyMaxBodyBytes = 64 << 10
	}
	if value.PolicyMaxBodyBytes < 1024 {
		return errors.New("config: policy_max_body_bytes must be between 1024 and 1048576")
	}
	if value.PolicyMaxInFlight < 0 || value.PolicyMaxInFlight > 4096 {
		return errors.New("config: policy_max_in_flight must be between 1 and 4096 when set")
	}
	if value.PolicyMaxInFlight == 0 {
		value.PolicyMaxInFlight = 64
	}
	return nil
}

func normalizeAbsoluteFile(value *string, field string, required bool) error {
	cleaned := strings.TrimSpace(*value)
	if cleaned == "" {
		if required {
			return fmt.Errorf("config: %s is required", field)
		}
		return nil
	}
	cleaned = filepath.Clean(cleaned)
	if !filepath.IsAbs(cleaned) || cleaned == string(filepath.Separator) {
		return fmt.Errorf("config: %s must be an absolute non-root file path", field)
	}
	*value = cleaned
	return nil
}

func normalizePGWUUEPools(value *PGWU) error {
	legacyConfigured := value.APN != "" || value.UEPoolPrefix != "" || value.UEGateway != ""
	if len(value.UEPools) != 0 && legacyConfigured {
		return errors.New("config: ue_pools cannot be combined with legacy top-level APN, ue_pool_prefix, or ue_gateway fields")
	}
	if len(value.UEPools) == 0 {
		if value.APN == "" || value.UEPoolPrefix == "" || value.UEGateway == "" {
			return errors.New("config: kernel-gtp requires ue_pools or one legacy APN, ue_pool_prefix, and ue_gateway")
		}
		value.UEPools = []PGWUUEPool{{APN: value.APN, UEPoolPrefix: value.UEPoolPrefix, UEGateway: value.UEGateway}}
	}
	seen := make(map[string]struct{}, len(value.UEPools))
	prefixes := make([]netip.Prefix, 0, len(value.UEPools))
	for index := range value.UEPools {
		pool := &value.UEPools[index]
		apn, err := normalizeAPNRoute(pool.APN)
		if err != nil {
			return fmt.Errorf("config: ue_pools[%d].apn: %w", index, err)
		}
		if _, exists := seen[apn]; exists {
			return fmt.Errorf("config: ue_pools[%d] duplicates APN %q", index, apn)
		}
		seen[apn] = struct{}{}
		prefix, err := Prefix(pool.UEPoolPrefix, fmt.Sprintf("ue_pools[%d].ue_pool_prefix", index))
		if err != nil {
			return err
		}
		if !prefix.Addr().Is4() || prefix.Bits() < 8 || prefix.Bits() > 30 || !netip.MustParsePrefix("10.0.0.0/8").Contains(prefix.Addr()) {
			return fmt.Errorf("config: ue_pools[%d].ue_pool_prefix must be an IPv4 /8../30 inside Lodestar 10.0.0.0/8 addressing", index)
		}
		gateway, err := Addr(pool.UEGateway, fmt.Sprintf("ue_pools[%d].ue_gateway", index))
		if err != nil {
			return err
		}
		if !prefix.Contains(gateway) {
			return fmt.Errorf("config: ue_pools[%d].ue_gateway must be inside its UE pool", index)
		}
		for otherIndex, other := range prefixes {
			if prefix.Contains(other.Addr()) || other.Contains(prefix.Addr()) {
				return fmt.Errorf("config: ue_pools[%d].ue_pool_prefix overlaps pool %d", index, otherIndex)
			}
		}
		pool.APN, pool.UEPoolPrefix, pool.UEGateway = apn, prefix.String(), gateway.String()
		prefixes = append(prefixes, prefix)
	}
	if legacyConfigured {
		pool := value.UEPools[0]
		value.APN, value.UEPoolPrefix, value.UEGateway = pool.APN, pool.UEPoolPrefix, pool.UEGateway
	}
	return nil
}

func LoadPGWU(path string) (PGWU, error) {
	var value PGWU
	if err := loadYAML(path, &value); err != nil {
		return PGWU{}, err
	}
	if value.ManagementListen == "" || value.PFCPListen == "" || value.PFCPAdvertise == "" || len(value.AllowedPGWC) == 0 ||
		value.S5GTPUListen == "" || len(value.AllowedSGWU) == 0 || value.TunnelName == "" {
		return PGWU{}, errors.New("config: PGW-U management, PFCP, S5-U, peer, and tunnel fields are required")
	}
	if value.PFCPEnterpriseID == 10415 {
		return PGWU{}, errors.New("config: PFCP enterprise ID 10415 is reserved for 3GPP")
	}
	if value.DatapathBackend == "" {
		value.DatapathBackend = "userspace-development"
	}
	switch value.DatapathBackend {
	case "userspace-development":
		if value.APN == "" {
			return PGWU{}, errors.New("config: userspace-development requires one APN")
		}
		if len(value.UEPools) != 0 {
			return PGWU{}, errors.New("config: ue_pools require the kernel-gtp datapath")
		}
		if value.Production {
			return PGWU{}, errors.New("config: userspace-development datapath is disabled in production mode")
		}
	case "kernel-gtp":
		if value.KernelGTPOwnerFile == "" {
			return PGWU{}, errors.New("config: kernel-gtp requires kernel_gtp_ownership_file")
		}
		if err := normalizePGWUUEPools(&value); err != nil {
			return PGWU{}, err
		}
	default:
		return PGWU{}, fmt.Errorf("config: PGW-U datapath backend %q is not available in this build", value.DatapathBackend)
	}
	if value.SocketBufferBytes < 0 || value.MaxPacketSize < 0 || value.MaxSessions < 0 || value.MaxPolicyFilters < 0 || value.StateWALMaxBytes < 0 {
		return PGWU{}, errors.New("config: PGW-U size and capacity fields cannot be negative")
	}
	if value.SocketBufferBytes == 0 {
		value.SocketBufferBytes = 16 * 1024 * 1024
	}
	if value.MaxPacketSize == 0 {
		value.MaxPacketSize = 65_535
	}
	if value.DebugListen == "" {
		value.DebugListen = "127.0.0.1:6061"
	}
	if err := requireLoopbackAddrPort(value.DebugListen, "debug_listen"); err != nil {
		return PGWU{}, err
	}
	if value.QERBurstDuration == "" {
		value.QERBurstDuration = "100ms"
	}
	qerBurst, err := Duration(value.QERBurstDuration, "qer_burst_duration")
	if err != nil {
		return PGWU{}, err
	}
	if qerBurst < time.Millisecond || qerBurst > time.Second {
		return PGWU{}, errors.New("config: PGW-U qer_burst_duration must be between 1ms and 1s")
	}
	if value.MaxSessions == 0 {
		value.MaxSessions = 1_000_000
	}
	qci1FieldCount := 0
	for _, field := range []string{value.QCI1S5GTPUListen, value.QCI1TunnelName, value.QCI1KernelGTPOwnerFile} {
		if field != "" {
			qci1FieldCount++
		}
	}
	qci1Configured := qci1FieldCount == 3
	if qci1FieldCount != 0 && !qci1Configured {
		return PGWU{}, errors.New("config: qci1_s5_gtpu_listen, qci1_tunnel_name, and qci1_kernel_gtp_ownership_file must be configured together")
	}
	if value.DatapathBackend != "kernel-gtp" && qci1FieldCount != 0 {
		return PGWU{}, errors.New("config: QCI 1 kernel-GTP fields require the kernel-gtp datapath")
	}
	if value.Production && value.DatapathBackend == "kernel-gtp" && !qci1Configured {
		return PGWU{}, errors.New("config: production kernel-gtp requires the QCI 1 S5-U address, tunnel, and ownership file")
	}
	if value.MaxPolicyFilters == 0 && qci1Configured {
		filters := int64(8_000_000)
		if value.MaxSessions <= 1_000_000 {
			filters = int64(value.MaxSessions) * 8
		}
		if filters < 1_024 {
			filters = 1_024
		}
		if filters > 8_000_000 {
			filters = 8_000_000
		}
		value.MaxPolicyFilters = int(filters)
	}
	if value.MaxPolicyFilters != 0 && !qci1Configured {
		return PGWU{}, errors.New("config: max_policy_filters requires the complete QCI 1 kernel-GTP configuration")
	}
	if !qci1Configured && (value.QCI1RouteTable != 0 || value.QCI1RulePriority != 0 || value.QCI1FirewallMark != 0 || value.QCI1FirewallMask != 0) {
		return PGWU{}, errors.New("config: QCI 1 policy-routing fields require the complete QCI 1 kernel-GTP configuration")
	}
	if qci1Configured {
		if value.QCI1RouteTable == 0 {
			value.QCI1RouteTable = 21_521
		}
		if value.QCI1RulePriority == 0 {
			value.QCI1RulePriority = 10_510
		}
		if value.QCI1FirewallMark == 0 {
			value.QCI1FirewallMark = 0x4c51_0000
		}
		if value.QCI1FirewallMask == 0 {
			value.QCI1FirewallMask = 0xffff_0000
		}
		if value.QCI1RouteTable == 252 || value.QCI1RouteTable == 253 || value.QCI1RouteTable == 254 || value.QCI1RouteTable == 255 {
			return PGWU{}, errors.New("config: qci1_route_table must not use a reserved Linux routing table")
		}
		if value.QCI1FirewallMark&^value.QCI1FirewallMask != 0 {
			return PGWU{}, errors.New("config: qci1_firewall_mark must contain no bits outside qci1_firewall_mask")
		}
	}
	if value.MaxPolicyFilters != 0 && (value.MaxPolicyFilters < 1_024 || value.MaxPolicyFilters > 8_000_000) {
		return PGWU{}, errors.New("config: max_policy_filters must be between 1024 and 8000000")
	}
	if value.StateFile != "" {
		value.StateFile = filepath.Clean(value.StateFile)
		if !filepath.IsAbs(value.StateFile) || value.StateFile == string(filepath.Separator) {
			return PGWU{}, errors.New("config: state_file must be an absolute file path")
		}
		if value.StateWALMaxBytes == 0 {
			value.StateWALMaxBytes = 1 << 30
		}
		if value.StateWALMaxBytes < 1<<20 {
			return PGWU{}, errors.New("config: state_wal_max_bytes must be at least 1048576")
		}
	} else if value.StateWALMaxBytes != 0 {
		return PGWU{}, errors.New("config: state_wal_max_bytes requires state_file")
	}
	if value.Production && value.StateFile == "" {
		return PGWU{}, errors.New("config: production PGW-U requires durable state_file")
	}
	if value.KernelGTPOwnerFile != "" {
		value.KernelGTPOwnerFile = filepath.Clean(value.KernelGTPOwnerFile)
		if !filepath.IsAbs(value.KernelGTPOwnerFile) || value.KernelGTPOwnerFile == string(filepath.Separator) {
			return PGWU{}, errors.New("config: kernel_gtp_ownership_file must be an absolute file path")
		}
	}
	if value.QCI1KernelGTPOwnerFile != "" {
		value.QCI1KernelGTPOwnerFile = filepath.Clean(value.QCI1KernelGTPOwnerFile)
		if !filepath.IsAbs(value.QCI1KernelGTPOwnerFile) || value.QCI1KernelGTPOwnerFile == string(filepath.Separator) {
			return PGWU{}, errors.New("config: qci1_kernel_gtp_ownership_file must be an absolute file path")
		}
		if value.QCI1KernelGTPOwnerFile == value.KernelGTPOwnerFile {
			return PGWU{}, errors.New("config: QCI 1 and default kernel-GTP ownership files must differ")
		}
	}
	if value.KernelGTPHashSize == 0 {
		value.KernelGTPHashSize = 131_072
	}
	if value.KernelGTPMTU == 0 {
		value.KernelGTPMTU = 1_400
	}
	if value.KernelGTPHashSize < 1_024 || value.KernelGTPHashSize > 16_777_216 {
		return PGWU{}, errors.New("config: kernel_gtp_hash_size must be between 1024 and 16777216")
	}
	if value.KernelGTPMTU < 1_280 || value.KernelGTPMTU > 1_452 {
		return PGWU{}, errors.New("config: kernel_gtp_mtu must be between 1280 and 1452 bytes")
	}
	if len(value.TunnelName) > 15 {
		return PGWU{}, errors.New("config: PGW-U tunnel_name must fit Linux's 15-character interface-name limit")
	}
	if len(value.QCI1TunnelName) > 15 {
		return PGWU{}, errors.New("config: PGW-U qci1_tunnel_name must fit Linux's 15-character interface-name limit")
	}
	if value.QCI1TunnelName != "" && value.QCI1TunnelName == value.TunnelName {
		return PGWU{}, errors.New("config: QCI 1 and default tunnel names must differ")
	}
	if value.RetransmitTimeout == "" {
		value.RetransmitTimeout = "1s"
	}
	if value.AssociationTimeout == "" {
		value.AssociationTimeout = "15s"
	}
	if value.GraceWindow == "" {
		value.GraceWindow = "120s"
	}
	if value.MaxRetransmits == 0 {
		value.MaxRetransmits = 3
	}
	if err := requireLodestarIPv4(value.PFCPAdvertise, "pfcp_advertise"); err != nil {
		return PGWU{}, err
	}
	if err := requireLodestarAddrPort(value.PFCPListen, "pfcp_listen"); err != nil {
		return PGWU{}, err
	}
	if err := requireLodestarAddresses(value.AllowedPGWC, "allowed_pgwc"); err != nil {
		return PGWU{}, err
	}
	if err := requireLodestarAddrPort(value.S5GTPUListen, "s5_gtpu_listen"); err != nil {
		return PGWU{}, err
	}
	if value.DatapathBackend == "kernel-gtp" {
		defaultS5, _ := AddrPort(value.S5GTPUListen, "s5_gtpu_listen")
		if defaultS5.Port() != 2152 {
			return PGWU{}, errors.New("config: kernel-gtp s5_gtpu_listen must use UDP port 2152")
		}
		if qci1Configured {
			if err := requireLodestarAddrPort(value.QCI1S5GTPUListen, "qci1_s5_gtpu_listen"); err != nil {
				return PGWU{}, err
			}
			qci1S5, _ := AddrPort(value.QCI1S5GTPUListen, "qci1_s5_gtpu_listen")
			if qci1S5.Port() != 2152 || qci1S5.Addr() == defaultS5.Addr() {
				return PGWU{}, errors.New("config: qci1_s5_gtpu_listen must use UDP port 2152 on a distinct IPv4 address")
			}
		}
	}
	if err := requireLodestarAddresses(value.AllowedSGWU, "allowed_sgwu"); err != nil {
		return PGWU{}, err
	}
	if err := requireLodestarAddrPort(value.ManagementListen, "management_listen"); err != nil {
		return PGWU{}, err
	}
	for field, duration := range map[string]string{
		"association_timeout": value.AssociationTimeout, "association_grace_window": value.GraceWindow,
		"retransmit_timeout": value.RetransmitTimeout,
	} {
		if _, err := Duration(duration, field); err != nil {
			return PGWU{}, err
		}
	}
	return value, nil
}

func Addr(value, field string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("config: %s: %w", field, err)
	}
	return addr.Unmap(), nil
}

func AddrPort(value, field string) (netip.AddrPort, error) {
	addr, err := netip.ParseAddrPort(value)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("config: %s: %w", field, err)
	}
	return netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port()), nil
}

func requireLoopbackAddrPort(value, field string) error {
	address, err := AddrPort(value, field)
	if err != nil {
		return err
	}
	if !address.Addr().IsLoopback() || address.Port() == 0 {
		return fmt.Errorf("config: %s must be a loopback address with a non-zero port", field)
	}
	return nil
}

func Addrs(values []string, field string) ([]netip.Addr, error) {
	out := make([]netip.Addr, len(values))
	for index, value := range values {
		addr, err := Addr(value, fmt.Sprintf("%s[%d]", field, index))
		if err != nil {
			return nil, err
		}
		out[index] = addr
	}
	return out, nil
}

func Duration(value, field string) (time.Duration, error) {
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return 0, fmt.Errorf("config: %s must be a positive Go duration", field)
	}
	return duration, nil
}

func NonNegativeDuration(value, field string) (time.Duration, error) {
	duration, err := time.ParseDuration(value)
	if err != nil || duration < 0 {
		return 0, fmt.Errorf("config: %s must be a non-negative Go duration", field)
	}
	return duration, nil
}

func Prefix(value, field string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("config: %s: %w", field, err)
	}
	return prefix.Masked(), nil
}

func load(path string, destination any) error {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		return loadYAML(path, destination)
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open config %s: %w", path, err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode config %s: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode config %s: trailing JSON value", path)
	}
	return nil
}

func loadYAML(path string, destination any) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open config %s: %w", path, err)
	}
	defer file.Close()
	decoder := yaml.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.KnownFields(true)
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode config %s: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode config %s: trailing YAML document", path)
	}
	return nil
}

func loadSubscriberSalt(destination *string, path string) error {
	if *destination == "" {
		contents, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("config: read subscriber salt file: %w", err)
		}
		*destination = strings.TrimSpace(string(contents))
	}
	if len(*destination) < 16 {
		return errors.New("config: subscriber salt must contain at least 16 characters")
	}
	return nil
}

func normalizeControlState(path *string, maxBytes *int64) error {
	if *maxBytes < 0 {
		return errors.New("config: state_wal_max_bytes cannot be negative")
	}
	cleaned := strings.TrimSpace(*path)
	if cleaned == "" {
		if *maxBytes != 0 {
			return errors.New("config: state_wal_max_bytes requires state_file")
		}
		*path = ""
		return nil
	}
	cleaned = filepath.Clean(cleaned)
	if !filepath.IsAbs(cleaned) || cleaned == string(filepath.Separator) {
		return errors.New("config: state_file must be an absolute non-root file path")
	}
	if *maxBytes == 0 {
		*maxBytes = 1 << 30
	}
	if *maxBytes < 1<<20 {
		return errors.New("config: state_wal_max_bytes must be at least 1048576")
	}
	*path = cleaned
	return nil
}

func normalizeAdmissionDrain(path, pollInterval *string) error {
	cleaned := strings.TrimSpace(*path)
	if cleaned == "" {
		if strings.TrimSpace(*pollInterval) != "" {
			return errors.New("config: admission_poll_interval requires admission_drain_file")
		}
		*path, *pollInterval = "", ""
		return nil
	}
	cleaned = filepath.Clean(cleaned)
	if len(cleaned) > 4096 || !filepath.IsAbs(cleaned) || cleaned == string(filepath.Separator) {
		return errors.New("config: admission_drain_file must be an absolute non-root file path")
	}
	if strings.TrimSpace(*pollInterval) == "" {
		*pollInterval = "250ms"
	}
	duration, err := Duration(*pollInterval, "admission_poll_interval")
	if err != nil {
		return err
	}
	if duration < 25*time.Millisecond || duration > 30*time.Second {
		return errors.New("config: admission_poll_interval must be between 25ms and 30s")
	}
	*path = cleaned
	*pollInterval = duration.String()
	return nil
}

func normalizeReconcileWorkers(workers *int) error {
	if *workers < 0 || *workers > 1024 {
		return errors.New("config: reconcile_workers must be between 1 and 1024 when set")
	}
	if *workers == 0 {
		*workers = 64
	}
	return nil
}

func requireLodestarIPv4(value, field string) error {
	addr, err := Addr(value, field)
	if err != nil {
		return err
	}
	if !addr.Is4() || !netip.MustParsePrefix("10.0.0.0/8").Contains(addr) {
		return fmt.Errorf("config: %s must use Lodestar 10.0.0.0/8 addressing", field)
	}
	return nil
}

func requireLodestarAddrPort(value, field string) error {
	address, err := AddrPort(value, field)
	if err != nil {
		return err
	}
	if address.Port() == 0 {
		return fmt.Errorf("config: %s requires a non-zero port", field)
	}
	return requireLodestarIPv4(address.Addr().String(), field)
}

func requireLodestarAddresses(values []string, field string) error {
	for index, value := range values {
		if err := requireLodestarIPv4(value, fmt.Sprintf("%s[%d]", field, index)); err != nil {
			return err
		}
	}
	return nil
}

func requireLodestarURL(value, field string) error {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		return fmt.Errorf("config: %s must be an HTTP(S) URL", field)
	}
	return requireLodestarIPv4(parsed.Hostname(), field)
}
