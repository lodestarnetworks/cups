// Package kernelgtp controls Linux's kernel GTP-U datapath through rtnetlink
// and generic netlink. It intentionally supports LTE GTPv1-U over IPv4 only;
// unsupported address families fail closed instead of falling back silently.
package kernelgtp

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
)

const (
	GTPUPort                 uint16 = 2152
	DefaultHashSize          uint32 = 131_072
	DefaultMTU               uint32 = 1_400
	DefaultSocketBufferBytes        = 16 * 1024 * 1024
	// PolicyRouteProtocol is deliberately outside the protocols assigned by
	// Linux's UAPI. It identifies only SGW Next-owned QCI 1 routes and rules;
	// table, priority, mark, mask, and link ownership are still verified before
	// any existing object is reclaimed.
	PolicyRouteProtocol  uint8 = 242
	ownershipAliasPrefix       = "sgw-next:kernel-gtp:v2:"
)

var (
	ErrUnsupported      = errors.New("kernel GTP is unsupported on this platform")
	ErrClosed           = errors.New("kernel GTP controller is closed")
	ErrInvalid          = errors.New("invalid kernel GTP configuration")
	ErrNotOwned         = errors.New("kernel GTP link is not owned by SGW Next")
	ErrOwnerActive      = errors.New("kernel GTP owner is already active")
	ErrIdentityConflict = errors.New("kernel GTP PDP identity conflict")
)

// Role controls which inner address the kernel uses for PDP lookup and
// anti-spoof validation. A PGW-facing tunnel endpoint is GGSN. The core side
// of an SGW relay is SGSN.
type Role uint32

const (
	RoleGGSN Role = iota
	RoleSGSN
)

func (r Role) String() string {
	switch r {
	case RoleGGSN:
		return "ggsn"
	case RoleSGSN:
		return "sgsn"
	default:
		return fmt.Sprintf("unknown(%d)", r)
	}
}

// LinkConfig describes one kernel GTP network device and its bound outer
// GTPv1-U socket. The outer address must already exist in the current network
// namespace.
type LinkConfig struct {
	Name              string
	OwnershipFile     string
	LocalIPv4         netip.Addr
	AllowedPeers      []netip.Addr
	Role              Role
	HashSize          uint32
	MTU               uint32
	RestartCounter    uint8
	SocketBufferBytes int
}

// Link is the validated identity of a kernel GTP network device.
type Link struct {
	Name           string
	Index          uint32
	Kind           string
	Alias          string
	Role           Role
	HashSize       uint32
	MTU            uint32
	RestartCounter uint8
	Recovery       RecoveryReport
}

// RecoveryReport records resources left by an abruptly terminated process and
// removed only after their durable ownership tokens were verified.
type RecoveryReport struct {
	LinkRemoved       bool
	PeerFilterRemoved bool
	PolicyRuleRemoved bool
}

// PolicyRoutingConfig reserves one IPv4 FIB table and one fwmark rule for a
// bearer-class GTP device. Mark must contain no bits outside Mask. Priority is
// an explicit operator-visible rule preference rather than an implicit global
// default, which lets multiple PGW-U instances coexist on one host safely.
type PolicyRoutingConfig struct {
	Table    uint32
	Priority uint32
	Mark     uint32
	Mask     uint32
}

// Context is one GTPv1-U PDP context. IncomingTEID is allocated locally and
// used to decapsulate packets. OutgoingTEID belongs to PeerIPv4 and is written
// into packets sent by the kernel.
type Context struct {
	LinkIndex    uint32
	UEIPv4       netip.Addr
	PeerIPv4     netip.Addr
	IncomingTEID uint32
	OutgoingTEID uint32
}

// ReconcileReport records the netlink operations required to make one link's
// kernel state match the desired PFCP-derived contexts.
type ReconcileReport struct {
	Created   int
	Updated   int
	Unchanged int
	Deleted   int
}

// PeerFilterCounters reports packets accepted from configured outer peers and
// packets dropped because their outer source was not allowlisted.
type PeerFilterCounters struct {
	AllowedPackets uint64
	AllowedBytes   uint64
	DroppedPackets uint64
	DroppedBytes   uint64
}

func normalizeLinkConfig(config LinkConfig) (LinkConfig, error) {
	config.Name = strings.TrimSpace(config.Name)
	config.OwnershipFile = filepath.Clean(strings.TrimSpace(config.OwnershipFile))
	config.LocalIPv4 = config.LocalIPv4.Unmap()
	if config.HashSize == 0 {
		config.HashSize = DefaultHashSize
	}
	if config.MTU == 0 {
		config.MTU = DefaultMTU
	}
	if config.SocketBufferBytes == 0 {
		config.SocketBufferBytes = DefaultSocketBufferBytes
	}
	if config.Name == "" || len(config.Name) > 15 || strings.ContainsAny(config.Name, "\x00/ \t\r\n") {
		return LinkConfig{}, fmt.Errorf("%w: link name must be 1-15 safe characters", ErrInvalid)
	}
	if config.OwnershipFile == "." || !filepath.IsAbs(config.OwnershipFile) || config.OwnershipFile == string(filepath.Separator) {
		return LinkConfig{}, fmt.Errorf("%w: ownership file must be an absolute non-root file path", ErrInvalid)
	}
	if err := validateIPv4("local outer", config.LocalIPv4); err != nil {
		return LinkConfig{}, err
	}
	if len(config.AllowedPeers) == 0 || len(config.AllowedPeers) > 64 {
		return LinkConfig{}, fmt.Errorf("%w: 1-64 allowed GTP-U peers are required", ErrInvalid)
	}
	seenPeers := make(map[netip.Addr]struct{}, len(config.AllowedPeers))
	peers := make([]netip.Addr, 0, len(config.AllowedPeers))
	for index, peer := range config.AllowedPeers {
		peer = peer.Unmap()
		if err := validateIPv4(fmt.Sprintf("allowed peer %d", index), peer); err != nil {
			return LinkConfig{}, err
		}
		if _, exists := seenPeers[peer]; exists {
			continue
		}
		seenPeers[peer] = struct{}{}
		peers = append(peers, peer)
	}
	config.AllowedPeers = peers
	if config.Role != RoleGGSN && config.Role != RoleSGSN {
		return LinkConfig{}, fmt.Errorf("%w: unsupported role %d", ErrInvalid, config.Role)
	}
	if config.HashSize < 1_024 || config.HashSize > 16_777_216 {
		return LinkConfig{}, fmt.Errorf("%w: hash size must be between 1024 and 16777216", ErrInvalid)
	}
	if config.MTU < 1_280 || config.MTU > 1_452 {
		return LinkConfig{}, fmt.Errorf("%w: MTU must be between 1280 and 1452", ErrInvalid)
	}
	if config.SocketBufferBytes < 65_536 || config.SocketBufferBytes > 1<<30 {
		return LinkConfig{}, fmt.Errorf("%w: socket buffer must be between 65536 and 1073741824 bytes", ErrInvalid)
	}
	return config, nil
}

func normalizeContext(context Context) (Context, error) {
	context.UEIPv4 = context.UEIPv4.Unmap()
	context.PeerIPv4 = context.PeerIPv4.Unmap()
	if context.LinkIndex == 0 {
		return Context{}, fmt.Errorf("%w: link index is required", ErrInvalid)
	}
	if err := validateIPv4("UE", context.UEIPv4); err != nil {
		return Context{}, err
	}
	if err := validateIPv4("peer", context.PeerIPv4); err != nil {
		return Context{}, err
	}
	if context.IncomingTEID == 0 || context.OutgoingTEID == 0 {
		return Context{}, fmt.Errorf("%w: incoming and outgoing TEIDs must be non-zero", ErrInvalid)
	}
	return context, nil
}

func normalizeIPv4Network(gateway netip.Addr, pool netip.Prefix) (netip.Addr, netip.Prefix, error) {
	gateway = gateway.Unmap()
	pool = pool.Masked()
	if err := validateIPv4("UE gateway", gateway); err != nil {
		return netip.Addr{}, netip.Prefix{}, err
	}
	if !pool.IsValid() || !pool.Addr().Is4() || pool.Bits() < 8 || !netip.MustParsePrefix("10.0.0.0/8").Contains(pool.Addr()) {
		return netip.Addr{}, netip.Prefix{}, fmt.Errorf("%w: UE pool must be an IPv4 prefix inside 10.0.0.0/8", ErrInvalid)
	}
	if !pool.Contains(gateway) {
		return netip.Addr{}, netip.Prefix{}, fmt.Errorf("%w: UE gateway must be inside the UE pool", ErrInvalid)
	}
	return gateway, pool, nil
}

func validateIPv4(label string, address netip.Addr) error {
	if !address.Is4() || address.IsUnspecified() || address.IsMulticast() {
		return fmt.Errorf("%w: %s address must be usable IPv4", ErrInvalid, label)
	}
	if !netip.MustParsePrefix("10.0.0.0/8").Contains(address) {
		return fmt.Errorf("%w: %s address must be inside 10.0.0.0/8", ErrInvalid, label)
	}
	return nil
}

func sameIdentity(a, b Context) bool {
	return a.LinkIndex == b.LinkIndex && a.UEIPv4 == b.UEIPv4 && a.IncomingTEID == b.IncomingTEID
}

func sameContext(a, b Context) bool {
	return sameIdentity(a, b) && a.PeerIPv4 == b.PeerIPv4 && a.OutgoingTEID == b.OutgoingTEID
}
