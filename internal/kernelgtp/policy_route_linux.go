//go:build linux

package kernelgtp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sort"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const (
	rtaTable = 15

	fraPriority = 6
	fraFWMark   = 10
	fraTable    = 15
	fraFWMask   = 16
	fraProtocol = 21

	fibRuleActionToTable = 1
	fibRuleHeaderSize    = 12
)

type installedPolicyRoute struct {
	link   Link
	prefix netip.Prefix
	config PolicyRoutingConfig
}

type installedPolicyRoutes struct {
	link   Link
	routes []installedPolicyRoute
	config PolicyRoutingConfig
}

type decodedPolicyRule struct {
	family      uint8
	table       uint32
	action      uint8
	priority    uint32
	mark        uint32
	mask        uint32
	protocol    uint8
	hasPriority bool
	hasMark     bool
	hasMask     bool
	hasProtocol bool
}

type decodedIPv4Route struct {
	table       uint32
	protocol    uint8
	scope       uint8
	routeType   uint8
	prefix      netip.Prefix
	outputIndex uint32
}

// ConfigurePolicyIPv4 installs the QCI 1 UE-pool route and fwmark rule using
// rtnetlink directly. It never shells out to ip(8). Existing objects sharing
// any reserved identity are rejected; an exact stale rule is reclaimed only
// when CreateLink has already proved and removed the matching owned crash
// leftover.
func (c *Controller) ConfigurePolicyIPv4(link Link, rawPool netip.Prefix, rawConfig PolicyRoutingConfig) (RecoveryReport, error) {
	return c.ConfigurePolicyIPv4Prefixes(link, []netip.Prefix{rawPool}, rawConfig)
}

// ConfigurePolicyIPv4Prefixes installs one fwmark rule and an exact route for
// every served UE pool. A single aggregate route is deliberately avoided: it
// could capture another site's or APN's 10/8 traffic during a policy lookup.
func (c *Controller) ConfigurePolicyIPv4Prefixes(link Link, rawPools []netip.Prefix, rawConfig PolicyRoutingConfig) (RecoveryReport, error) {
	pools, config, err := normalizePolicyRoutingPrefixes(rawPools, rawConfig)
	if err != nil {
		return RecoveryReport{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkOpen(); err != nil {
		return RecoveryReport{}, err
	}
	current, err := c.inspectLink(link.Index)
	if err != nil {
		return RecoveryReport{}, err
	}
	owned, ok := c.links[link.Index]
	if !ok || owned.Alias != link.Alias || current.Kind != gtpFamilyName || current.Alias != link.Alias || current.Name != link.Name {
		return RecoveryReport{}, fmt.Errorf("configure policy routing on link %q: %w", link.Name, ErrNotOwned)
	}
	if _, exists := c.policyRoutes[link.Index]; exists {
		return RecoveryReport{}, fmt.Errorf("configure policy routing on link %q twice: %w", link.Name, ErrInvalid)
	}

	routes, err := c.listIPv4Routes(config.Table)
	if err != nil {
		return RecoveryReport{}, fmt.Errorf("inspect policy routing table %d: %w", config.Table, err)
	}
	if len(routes) != 0 {
		return RecoveryReport{}, fmt.Errorf("reserve policy routing table %d: contains %d foreign routes: %w", config.Table, len(routes), ErrNotOwned)
	}

	rules, err := c.listIPv4PolicyRules()
	if err != nil {
		return RecoveryReport{}, fmt.Errorf("inspect IPv4 policy rules: %w", err)
	}
	var exact *decodedPolicyRule
	for index := range rules {
		candidate := rules[index]
		if samePolicyRule(candidate, config) {
			if exact != nil {
				return RecoveryReport{}, fmt.Errorf("reserve policy rule priority %d: duplicate exact rules: %w", config.Priority, ErrNotOwned)
			}
			exact = &candidate
			continue
		}
		if candidate.hasPriority && candidate.priority == config.Priority ||
			candidate.hasMark && candidate.hasMask && candidate.mark == config.Mark && candidate.mask == config.Mask ||
			candidate.table == config.Table && candidate.hasMark {
			return RecoveryReport{}, fmt.Errorf("reserve policy table=%d priority=%d mark=%#x/%#x: conflicting foreign rule: %w",
				config.Table, config.Priority, config.Mark, config.Mask, ErrNotOwned)
		}
	}
	recovery := RecoveryReport{}
	if exact != nil {
		if !link.Recovery.LinkRemoved {
			return RecoveryReport{}, fmt.Errorf("reclaim exact policy rule without an ownership-verified stale link: %w", ErrNotOwned)
		}
		if err := c.deleteIPv4PolicyRule(config); err != nil {
			return RecoveryReport{}, fmt.Errorf("remove stale owned IPv4 policy rule: %w", err)
		}
		recovery.PolicyRuleRemoved = true
	}

	installed := installedPolicyRoutes{link: link, config: config, routes: make([]installedPolicyRoute, 0, len(pools))}
	for _, pool := range pools {
		route := installedPolicyRoute{link: link, prefix: pool, config: config}
		if err := c.addPolicyIPv4Route(route); err != nil {
			rollbackErr := c.deletePolicyIPv4Routes(installed.routes)
			return RecoveryReport{}, errors.Join(
				fmt.Errorf("route UE pool %s through QCI 1 link %s in table %d: %w", pool, link.Name, config.Table, err),
				rollbackErr,
			)
		}
		installed.routes = append(installed.routes, route)
	}
	if err := c.addIPv4PolicyRule(config); err != nil {
		rollbackErr := c.deletePolicyIPv4Routes(installed.routes)
		return RecoveryReport{}, errors.Join(fmt.Errorf("install QCI 1 fwmark policy rule: %w", err), rollbackErr)
	}
	c.policyRoutes[link.Index] = installed
	updated := c.links[link.Index]
	updated.Recovery.PolicyRuleRemoved = updated.Recovery.PolicyRuleRemoved || recovery.PolicyRuleRemoved
	c.links[link.Index] = updated
	return recovery, nil
}

func normalizePolicyRoutingPrefixes(rawPools []netip.Prefix, rawConfig PolicyRoutingConfig) ([]netip.Prefix, PolicyRoutingConfig, error) {
	if len(rawPools) == 0 || len(rawPools) > 256 {
		return nil, PolicyRoutingConfig{}, fmt.Errorf("%w: policy routing requires between 1 and 256 UE pools", ErrInvalid)
	}
	pools := make([]netip.Prefix, 0, len(rawPools))
	config := rawConfig
	for index, rawPool := range rawPools {
		pool, normalized, err := normalizePolicyRouting(rawPool, rawConfig)
		if err != nil {
			return nil, PolicyRoutingConfig{}, fmt.Errorf("UE pool %d: %w", index, err)
		}
		config = normalized
		for otherIndex, other := range pools {
			if pool.Contains(other.Addr()) || other.Contains(pool.Addr()) {
				return nil, PolicyRoutingConfig{}, fmt.Errorf("%w: UE pool %d overlaps pool %d", ErrInvalid, index, otherIndex)
			}
		}
		pools = append(pools, pool)
	}
	sort.Slice(pools, func(left, right int) bool {
		if pools[left].Addr() != pools[right].Addr() {
			return pools[left].Addr().Less(pools[right].Addr())
		}
		return pools[left].Bits() < pools[right].Bits()
	})
	return pools, config, nil
}

func normalizePolicyRouting(rawPool netip.Prefix, config PolicyRoutingConfig) (netip.Prefix, PolicyRoutingConfig, error) {
	pool := rawPool.Masked()
	if !pool.IsValid() || !pool.Addr().Is4() || pool.Bits() < 8 || !netip.MustParsePrefix("10.0.0.0/8").Contains(pool.Addr()) {
		return netip.Prefix{}, PolicyRoutingConfig{}, fmt.Errorf("%w: UE pool must be an IPv4 prefix inside 10.0.0.0/8", ErrInvalid)
	}
	if config.Table == 0 || config.Table == unix.RT_TABLE_COMPAT || config.Table == unix.RT_TABLE_DEFAULT ||
		config.Table == unix.RT_TABLE_MAIN || config.Table == unix.RT_TABLE_LOCAL {
		return netip.Prefix{}, PolicyRoutingConfig{}, fmt.Errorf("%w: policy route table must not be reserved or zero", ErrInvalid)
	}
	if config.Priority == 0 {
		return netip.Prefix{}, PolicyRoutingConfig{}, fmt.Errorf("%w: policy rule priority must be non-zero", ErrInvalid)
	}
	if config.Mark == 0 || config.Mask == 0 || config.Mark&^config.Mask != 0 {
		return netip.Prefix{}, PolicyRoutingConfig{}, fmt.Errorf("%w: policy mark must be non-zero and contained by its mask", ErrInvalid)
	}
	return pool, config, nil
}

func (c *Controller) removePolicyRoutes(installed installedPolicyRoutes) error {
	ruleErr := c.deleteIPv4PolicyRule(installed.config)
	routeErr := c.deletePolicyIPv4Routes(installed.routes)
	return errors.Join(ruleErr, routeErr)
}

func (c *Controller) deletePolicyIPv4Routes(routes []installedPolicyRoute) error {
	var result error
	for index := len(routes) - 1; index >= 0; index-- {
		result = errors.Join(result, c.deletePolicyIPv4Route(routes[index]))
	}
	return result
}

func (c *Controller) addPolicyIPv4Route(installed installedPolicyRoute) error {
	return c.changePolicyIPv4Route(unix.RTM_NEWROUTE,
		netlink.Request|netlink.Acknowledge|netlink.Create|netlink.Excl, installed)
}

func (c *Controller) deletePolicyIPv4Route(installed installedPolicyRoute) error {
	err := c.changePolicyIPv4Route(unix.RTM_DELROUTE, netlink.Request|netlink.Acknowledge, installed)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENODEV) {
		return nil
	}
	return err
}

func (c *Controller) changePolicyIPv4Route(messageType uint16, flags netlink.HeaderFlags, installed installedPolicyRoute) error {
	raw := installed.prefix.Addr().As4()
	encoder := netlink.NewAttributeEncoder()
	encoder.Bytes(rtaDestination, raw[:])
	encoder.Uint32(rtaOutput, installed.link.Index)
	if installed.config.Table > 255 {
		encoder.Uint32(rtaTable, installed.config.Table)
	}
	attributes, err := encoder.Encode()
	if err != nil {
		return err
	}
	table := uint8(installed.config.Table)
	if installed.config.Table > 255 {
		table = unix.RT_TABLE_UNSPEC
	}
	request := netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(messageType), Flags: flags},
		Data: append(marshalRoute(unix.RtMsg{
			Family: unix.AF_INET, Dst_len: uint8(installed.prefix.Bits()), Table: table,
			Protocol: PolicyRouteProtocol, Scope: unix.RT_SCOPE_LINK, Type: unix.RTN_UNICAST,
		}), attributes...),
	}
	_, err = c.route.Execute(request)
	return err
}

func (c *Controller) addIPv4PolicyRule(config PolicyRoutingConfig) error {
	return c.changeIPv4PolicyRule(unix.RTM_NEWRULE,
		netlink.Request|netlink.Acknowledge|netlink.Create|netlink.Excl, config)
}

func (c *Controller) deleteIPv4PolicyRule(config PolicyRoutingConfig) error {
	err := c.changeIPv4PolicyRule(unix.RTM_DELRULE, netlink.Request|netlink.Acknowledge, config)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) {
		return nil
	}
	return err
}

func (c *Controller) changeIPv4PolicyRule(messageType uint16, flags netlink.HeaderFlags, config PolicyRoutingConfig) error {
	encoder := netlink.NewAttributeEncoder()
	encoder.Uint32(fraPriority, config.Priority)
	encoder.Uint32(fraFWMark, config.Mark)
	encoder.Uint32(fraFWMask, config.Mask)
	encoder.Uint32(fraTable, config.Table)
	encoder.Uint8(fraProtocol, PolicyRouteProtocol)
	attributes, err := encoder.Encode()
	if err != nil {
		return err
	}
	header := make([]byte, fibRuleHeaderSize)
	header[0] = unix.AF_INET
	if config.Table <= 255 {
		header[4] = uint8(config.Table)
	}
	header[7] = fibRuleActionToTable
	request := netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(messageType), Flags: flags},
		Data:   append(header, attributes...),
	}
	_, err = c.route.Execute(request)
	return err
}

func (c *Controller) listIPv4PolicyRules() ([]decodedPolicyRule, error) {
	header := make([]byte, fibRuleHeaderSize)
	header[0] = unix.AF_INET
	messages, err := c.route.Execute(netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(unix.RTM_GETRULE), Flags: netlink.Request | netlink.Dump},
		Data:   header,
	})
	if err != nil {
		return nil, err
	}
	out := make([]decodedPolicyRule, 0, len(messages))
	for index, message := range messages {
		decoded, supported, err := decodePolicyRule(message.Data)
		if err != nil {
			return nil, fmt.Errorf("decode rule %d: %w", index, err)
		}
		if supported {
			out = append(out, decoded)
		}
	}
	return out, nil
}

func decodePolicyRule(data []byte) (decodedPolicyRule, bool, error) {
	if len(data) < fibRuleHeaderSize {
		return decodedPolicyRule{}, false, errors.New("short fib-rule header")
	}
	if data[0] != unix.AF_INET {
		return decodedPolicyRule{}, false, nil
	}
	out := decodedPolicyRule{family: data[0], table: uint32(data[4]), action: data[7]}
	decoder, err := netlink.NewAttributeDecoder(data[fibRuleHeaderSize:])
	if err != nil {
		return decodedPolicyRule{}, false, err
	}
	for decoder.Next() {
		switch decoder.Type() {
		case fraPriority:
			out.priority, out.hasPriority = decoder.Uint32(), true
		case fraFWMark:
			out.mark, out.hasMark = decoder.Uint32(), true
		case fraFWMask:
			out.mask, out.hasMask = decoder.Uint32(), true
		case fraTable:
			out.table = decoder.Uint32()
		case fraProtocol:
			out.protocol, out.hasProtocol = decoder.Uint8(), true
		}
	}
	return out, true, decoder.Err()
}

func samePolicyRule(rule decodedPolicyRule, config PolicyRoutingConfig) bool {
	return rule.family == unix.AF_INET && rule.action == fibRuleActionToTable &&
		rule.table == config.Table && rule.hasPriority && rule.priority == config.Priority &&
		rule.hasMark && rule.mark == config.Mark && rule.hasMask && rule.mask == config.Mask &&
		rule.hasProtocol && rule.protocol == PolicyRouteProtocol
}

func (c *Controller) listIPv4Routes(table uint32) ([]decodedIPv4Route, error) {
	messages, err := c.route.Execute(netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(unix.RTM_GETROUTE), Flags: netlink.Request | netlink.Dump},
		Data:   marshalRoute(unix.RtMsg{Family: unix.AF_INET}),
	})
	if err != nil {
		return nil, err
	}
	out := make([]decodedIPv4Route, 0)
	for index, message := range messages {
		decoded, supported, err := decodeIPv4Route(message.Data)
		if err != nil {
			return nil, fmt.Errorf("decode route %d: %w", index, err)
		}
		if supported && decoded.table == table {
			out = append(out, decoded)
		}
	}
	return out, nil
}

func decodeIPv4Route(data []byte) (decodedIPv4Route, bool, error) {
	if len(data) < unix.SizeofRtMsg {
		return decodedIPv4Route{}, false, errors.New("short route header")
	}
	if data[0] != unix.AF_INET {
		return decodedIPv4Route{}, false, nil
	}
	bits := int(data[1])
	if bits < 0 || bits > 32 {
		return decodedIPv4Route{}, false, errors.New("invalid IPv4 route prefix length")
	}
	out := decodedIPv4Route{
		table: uint32(data[4]), protocol: data[5], scope: data[6], routeType: data[7],
		prefix: netip.PrefixFrom(netip.IPv4Unspecified(), bits),
	}
	decoder, err := netlink.NewAttributeDecoder(data[unix.SizeofRtMsg:])
	if err != nil {
		return decodedIPv4Route{}, false, err
	}
	for decoder.Next() {
		switch decoder.Type() {
		case rtaDestination:
			raw := decoder.Bytes()
			if len(raw) != 4 {
				return decodedIPv4Route{}, false, errors.New("invalid IPv4 route destination")
			}
			out.prefix = netip.PrefixFrom(netip.AddrFrom4([4]byte(raw)), bits).Masked()
		case rtaOutput:
			out.outputIndex = decoder.Uint32()
		case rtaTable:
			out.table = decoder.Uint32()
		}
	}
	if err := decoder.Err(); err != nil {
		return decodedIPv4Route{}, false, err
	}
	return out, true, nil
}

func marshalPolicyRuleForTest(config PolicyRoutingConfig) ([]byte, error) {
	encoder := netlink.NewAttributeEncoder()
	encoder.Uint32(fraPriority, config.Priority)
	encoder.Uint32(fraFWMark, config.Mark)
	encoder.Uint32(fraFWMask, config.Mask)
	encoder.Uint32(fraTable, config.Table)
	encoder.Uint8(fraProtocol, PolicyRouteProtocol)
	attributes, err := encoder.Encode()
	if err != nil {
		return nil, err
	}
	header := make([]byte, fibRuleHeaderSize)
	header[0], header[7] = unix.AF_INET, fibRuleActionToTable
	binary.NativeEndian.PutUint32(header[8:12], 0)
	return append(header, attributes...), nil
}
