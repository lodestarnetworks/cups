//go:build linux

package kernelgtp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"sync"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const (
	gtpFamilyName    = "gtp"
	gtpFamilyVersion = 0
)

const (
	gtpCommandNewPDP = iota
	gtpCommandDeletePDP
	gtpCommandGetPDP
)

const (
	gtpAttributeUnspecified = iota
	gtpAttributeLink        = iota
	gtpAttributeVersion
	gtpAttributeTID
	gtpAttributePeerAddress
	gtpAttributeMSAddress
	gtpAttributeFlow
	gtpAttributeNetNSFD
	gtpAttributeIncomingTEID
	gtpAttributeOutgoingTEID
)

const (
	gtpVersion1 = 1

	iflaIfName   = 3
	iflaMTU      = 4
	iflaLinkInfo = 18
	iflaIfAlias  = 20

	iflaInfoKind = 1
	iflaInfoData = 2

	iflaGTPFD1          = 2
	iflaGTPPDPHashSize  = 3
	iflaGTPRole         = 4
	iflaGTPRestartCount = 6

	ifaAddress = 1
	ifaLocal   = 2

	rtaDestination = 1
	rtaOutput      = 4
)

type routeExecutor interface {
	Execute(netlink.Message) ([]netlink.Message, error)
	Close() error
}

type genericExecutor interface {
	Execute(genetlink.Message, uint16, netlink.HeaderFlags) ([]genetlink.Message, error)
	Close() error
}

// Controller owns the GTP links, sockets, and peer firewalls it creates. Each
// link is fenced by a locked ownership file and a random durable token carried
// by both the netdevice and nftables table. A restart can therefore remove its
// own crash leftovers without adopting or mutating similarly named objects.
type Controller struct {
	mu           sync.Mutex
	route        routeExecutor
	generic      genericExecutor
	family       uint16
	sockets      map[uint32]int
	filters      map[uint32]*peerFirewall
	policyRoutes map[uint32]installedPolicyRoutes
	owners       map[uint32]*ownerLease
	links        map[uint32]Link
	closed       bool
}

// Open connects to rtnetlink and resolves the kernel's GTP generic-netlink
// family. It does not create an interface, bind a UDP port, or alter routes.
func Open() (*Controller, error) {
	route, err := netlink.Dial(unix.NETLINK_ROUTE, &netlink.Config{Strict: true})
	if err != nil {
		return nil, fmt.Errorf("open rtnetlink: %w", err)
	}
	generic, err := genetlink.Dial(&netlink.Config{Strict: true})
	if err != nil {
		_ = route.Close()
		return nil, fmt.Errorf("open generic netlink: %w", err)
	}
	family, err := generic.GetFamily(gtpFamilyName)
	if err != nil {
		_ = generic.Close()
		_ = route.Close()
		return nil, fmt.Errorf("resolve %q generic-netlink family: %w", gtpFamilyName, err)
	}
	return &Controller{
		route: route, generic: generic, family: family.ID,
		sockets: make(map[uint32]int), filters: make(map[uint32]*peerFirewall),
		policyRoutes: make(map[uint32]installedPolicyRoutes),
		owners:       make(map[uint32]*ownerLease), links: make(map[uint32]Link),
	}, nil
}

// Close removes links created by this controller before releasing their bound
// UDP sockets. A userspace-supplied GTP socket must remain open for the link's
// lifetime; leaving the netdevice behind after closing it would create a
// misleading but non-forwarding zombie interface.
func (c *Controller) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	var result error
	for index, link := range c.links {
		if policyRoutes, ok := c.policyRoutes[index]; ok {
			result = errors.Join(result, c.removePolicyRoutes(policyRoutes))
			delete(c.policyRoutes, index)
		}
		result = errors.Join(result, c.deleteOwnedLink(link))
		if fd, ok := c.sockets[index]; ok {
			result = errors.Join(result, unix.Close(fd))
		}
		delete(c.sockets, index)
		if filter, ok := c.filters[index]; ok {
			result = errors.Join(result, filter.Close())
		}
		delete(c.filters, index)
		if owner, ok := c.owners[index]; ok {
			result = errors.Join(result, owner.Close())
		}
		delete(c.owners, index)
		delete(c.links, index)
	}
	return errors.Join(result, c.generic.Close(), c.route.Close())
}

// CreateLink creates an ownership-fenced kernel GTP device around a UDP socket
// bound to LocalIPv4:2152. It first removes stale objects only when both their
// kernel-resident tokens exactly match the locked durable owner record.
func (c *Controller) CreateLink(raw LinkConfig) (_ Link, resultErr error) {
	config, err := normalizeLinkConfig(raw)
	if err != nil {
		return Link{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkOpen(); err != nil {
		return Link{}, err
	}
	owner, err := acquireOwnerLease(config)
	if err != nil {
		return Link{}, err
	}
	keepOwner := false
	defer func() {
		if !keepOwner {
			resultErr = errors.Join(resultErr, owner.Close())
		}
	}()
	recovery, err := c.removeCrashLeftovers(config, owner)
	if err != nil {
		return Link{}, err
	}

	fd, err := openGTPSocket(config.LocalIPv4, config.SocketBufferBytes)
	if err != nil {
		return Link{}, err
	}
	keepSocket := false
	defer func() {
		if !keepSocket {
			_ = unix.Close(fd)
		}
	}()
	filter, err := createPeerFirewall(config.Name, config.LocalIPv4, config.AllowedPeers, peerFirewallOwnerPrefix+owner.token)
	if err != nil {
		return Link{}, err
	}
	keepFilter := false
	defer func() {
		if !keepFilter {
			resultErr = errors.Join(resultErr, filter.Close())
		}
	}()

	attributes, err := encodeLinkAttributes(config, fd, owner.alias)
	if err != nil {
		return Link{}, err
	}
	request := netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(unix.RTM_NEWLINK),
			Flags: netlink.Request | netlink.Acknowledge | netlink.Create | netlink.Excl,
		},
		Data: append(marshalIfInfo(unix.IfInfomsg{Family: unix.AF_UNSPEC}), attributes...),
	}
	if _, err := c.route.Execute(request); err != nil {
		return Link{}, fmt.Errorf("create kernel GTP link %q: %w", config.Name, err)
	}
	created, exists, err := findInterface(config.Name)
	if err != nil || !exists {
		if err == nil {
			err = os.ErrNotExist
		}
		return Link{}, fmt.Errorf("resolve newly created GTP link %q: %w", config.Name, err)
	}
	if err := c.setLinkAlias(uint32(created.Index), owner.alias); err != nil {
		cleanupErr := c.deleteLinkByIndex(uint32(created.Index))
		return Link{}, errors.Join(fmt.Errorf("mark GTP link %q ownership: %w", config.Name, err), cleanupErr)
	}
	if err := disableIPv6(config.Name); err != nil {
		cleanupErr := c.deleteLinkByIndex(uint32(created.Index))
		return Link{}, errors.Join(fmt.Errorf("disable unsupported IPv6 on GTP link %q: %w", config.Name, err), cleanupErr)
	}
	if err := c.setLinkUp(uint32(created.Index)); err != nil {
		cleanupErr := c.deleteLinkByIndex(uint32(created.Index))
		return Link{}, errors.Join(fmt.Errorf("bring GTP link %q up: %w", config.Name, err), cleanupErr)
	}
	link, err := c.inspectLink(uint32(created.Index))
	if err != nil {
		cleanupErr := c.deleteLinkByIndex(uint32(created.Index))
		return Link{}, errors.Join(fmt.Errorf("verify GTP link %q: %w", config.Name, err), cleanupErr)
	}
	if link.Kind != gtpFamilyName || link.Alias != owner.alias || link.Role != config.Role || link.Name != config.Name {
		cleanupErr := c.deleteLinkByIndex(uint32(created.Index))
		return Link{}, errors.Join(fmt.Errorf("verify GTP link %q metadata %+v: %w", config.Name, link, ErrNotOwned), cleanupErr)
	}
	link.Recovery = recovery
	c.sockets[link.Index] = fd
	c.filters[link.Index] = filter
	c.owners[link.Index] = owner
	c.links[link.Index] = link
	keepSocket = true
	keepFilter = true
	keepOwner = true
	return link, nil
}

func (c *Controller) removeCrashLeftovers(config LinkConfig, owner *ownerLease) (RecoveryReport, error) {
	device, linkExists, err := findInterface(config.Name)
	if err != nil {
		return RecoveryReport{}, fmt.Errorf("check stale GTP link %q: %w", config.Name, err)
	}
	filter, filterExists, err := inspectOwnedPeerFirewall(config.Name, peerFirewallOwnerPrefix+owner.token)
	if err != nil {
		return RecoveryReport{}, fmt.Errorf("check stale GTP-U peer filter for %q: %w", config.Name, err)
	}
	var stale Link
	if linkExists {
		stale, err = c.inspectLink(uint32(device.Index))
		if err != nil {
			return RecoveryReport{}, fmt.Errorf("inspect stale GTP link %q: %w", config.Name, err)
		}
		if stale.Name != config.Name || stale.Kind != gtpFamilyName || stale.Alias != owner.alias {
			return RecoveryReport{}, fmt.Errorf("recover stale GTP link %q: %w", config.Name, ErrNotOwned)
		}
	}
	// Verification of both objects completes before either is mutated. This
	// keeps a foreign nftables table from causing a partially destructive
	// recovery when the interface name happens to match.
	if linkExists {
		if err := c.deleteLinkByIndex(stale.Index); err != nil {
			return RecoveryReport{}, fmt.Errorf("remove stale owned GTP link %q: %w", config.Name, err)
		}
	}
	if filterExists {
		if err := filter.Close(); err != nil {
			return RecoveryReport{}, fmt.Errorf("remove stale owned GTP-U peer filter for %q: %w", config.Name, err)
		}
	}
	return RecoveryReport{LinkRemoved: linkExists, PeerFilterRemoved: filterExists}, nil
}

func disableIPv6(linkName string) (result error) {
	path := "/proc/sys/net/ipv6/conf/" + linkName + "/disable_ipv6"
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		// Kernels built without IPv6 already satisfy the IPv4-only policy.
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, unix.Close(fd)) }()
	written, err := unix.Write(fd, []byte("1"))
	if err != nil {
		return err
	}
	if written != 1 {
		return fmt.Errorf("short sysctl write: wrote %d bytes", written)
	}
	return nil
}

// InspectLink verifies the type and ownership marker before returning link
// metadata. It does not adopt a userspace socket from another process.
func (c *Controller) InspectLink(name string) (Link, error) {
	name = stringTrim(name)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkOpen(); err != nil {
		return Link{}, err
	}
	device, exists, err := findInterface(name)
	if err != nil || !exists {
		if err == nil {
			err = os.ErrNotExist
		}
		return Link{}, fmt.Errorf("find GTP link %q: %w", name, err)
	}
	link, err := c.inspectLink(uint32(device.Index))
	if err != nil {
		return Link{}, err
	}
	if link.Kind != gtpFamilyName || !isOwnershipAlias(link.Alias) {
		return Link{}, fmt.Errorf("inspect GTP link %q: %w", name, ErrNotOwned)
	}
	return link, nil
}

// DeleteLink deletes only a link created by this live, fenced controller. A
// newly opened controller cannot use this method to adopt a stale link;
// ownership-verified stale cleanup occurs only as part of CreateLink.
func (c *Controller) DeleteLink(name string) error {
	name = stringTrim(name)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkOpen(); err != nil {
		return err
	}
	var link Link
	found := false
	for _, candidate := range c.links {
		if candidate.Name == name {
			link = candidate
			found = true
			break
		}
	}
	if !found {
		_, exists, err := findInterface(name)
		if err != nil {
			return fmt.Errorf("find GTP link %q: %w", name, err)
		}
		if exists {
			return fmt.Errorf("delete GTP link %q: %w", name, ErrNotOwned)
		}
		return nil
	}
	if policyRoutes, ok := c.policyRoutes[link.Index]; ok {
		if err := c.removePolicyRoutes(policyRoutes); err != nil {
			return err
		}
		delete(c.policyRoutes, link.Index)
	}
	if err := c.deleteOwnedLink(link); err != nil {
		return err
	}
	var result error
	if fd, ok := c.sockets[link.Index]; ok {
		delete(c.sockets, link.Index)
		if err := unix.Close(fd); err != nil {
			result = errors.Join(result, fmt.Errorf("close GTP-U socket for link %q: %w", name, err))
		}
	}
	if filter, ok := c.filters[link.Index]; ok {
		delete(c.filters, link.Index)
		if err := filter.Close(); err != nil {
			result = errors.Join(result, err)
		}
	}
	if owner, ok := c.owners[link.Index]; ok {
		delete(c.owners, link.Index)
		result = errors.Join(result, owner.Close())
	}
	delete(c.links, link.Index)
	return result
}

func (c *Controller) deleteOwnedLink(expected Link) error {
	device, exists, err := findInterface(expected.Name)
	if err != nil {
		return fmt.Errorf("find owned GTP link %q: %w", expected.Name, err)
	}
	if !exists {
		return nil
	}
	if uint32(device.Index) != expected.Index {
		return fmt.Errorf("delete GTP link %q: index changed from %d to %d: %w", expected.Name, expected.Index, device.Index, ErrNotOwned)
	}
	current, err := c.inspectLink(expected.Index)
	if err != nil {
		return err
	}
	if current.Name != expected.Name || current.Kind != gtpFamilyName || current.Alias != expected.Alias || !isOwnershipAlias(current.Alias) {
		return fmt.Errorf("delete GTP link %q: %w", expected.Name, ErrNotOwned)
	}
	return c.deleteLinkByIndex(expected.Index)
}

// PeerFilterCounters returns nftables counters for the exact firewall owned by
// this controller and link.
func (c *Controller) PeerFilterCounters(link Link) (PeerFilterCounters, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkOpen(); err != nil {
		return PeerFilterCounters{}, err
	}
	filter, ok := c.filters[link.Index]
	if !ok {
		return PeerFilterCounters{}, fmt.Errorf("read GTP-U peer filter for link %q: %w", link.Name, ErrNotOwned)
	}
	return filter.Counters()
}

// ConfigureIPv4 assigns the APN gateway as a /32 and routes the UE pool to an
// SGW Next-owned GTP device. Link deletion removes both kernel objects.
func (c *Controller) ConfigureIPv4(link Link, rawGateway netip.Addr, rawPool netip.Prefix) error {
	gateway, pool, err := normalizeIPv4Network(rawGateway, rawPool)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkOpen(); err != nil {
		return err
	}
	current, err := c.inspectLink(link.Index)
	if err != nil {
		return err
	}
	owned, ok := c.links[link.Index]
	if !ok || owned.Alias != link.Alias || current.Kind != gtpFamilyName || current.Alias != link.Alias || current.Name != link.Name {
		return fmt.Errorf("configure IPv4 on link %q: %w", link.Name, ErrNotOwned)
	}
	if err := c.addIPv4Address(link.Index, gateway); err != nil {
		return fmt.Errorf("assign UE gateway %s to %s: %w", gateway, link.Name, err)
	}
	if err := c.addIPv4Route(link.Index, pool); err != nil {
		rollbackErr := c.deleteIPv4Address(link.Index, gateway)
		return errors.Join(fmt.Errorf("route UE pool %s to %s: %w", pool, link.Name, err), rollbackErr)
	}
	return nil
}

// AddContext installs a new context and fails if either its UE address or
// incoming TEID already exists on the link.
func (c *Controller) AddContext(raw Context) error {
	context, err := normalizeContext(raw)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkOpen(); err != nil {
		return err
	}
	return c.addContext(context, true)
}

// EnsureContext creates a missing context or replaces only its peer/outgoing
// tunnel fields. UE address and incoming TEID are immutable identities. Linux
// GTP has no in-place update operation, so replacement is delete/add with
// rollback if the add fails.
func (c *Controller) EnsureContext(raw Context) (bool, error) {
	context, err := normalizeContext(raw)
	if err != nil {
		return false, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkOpen(); err != nil {
		return false, err
	}
	existing, err := c.getContext(context.LinkIndex, context.IncomingTEID)
	if errors.Is(err, os.ErrNotExist) {
		if err := c.addContext(context, true); err != nil {
			return false, err
		}
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if !sameIdentity(existing, context) {
		return false, fmt.Errorf("ensure PDP context: %w", ErrIdentityConflict)
	}
	if sameContext(existing, context) {
		return false, nil
	}
	return true, c.replaceContext(existing, context)
}

// DeleteContext removes a context idempotently by link and incoming TEID.
func (c *Controller) DeleteContext(linkIndex, incomingTEID uint32) error {
	if linkIndex == 0 || incomingTEID == 0 {
		return fmt.Errorf("%w: link index and incoming TEID are required", ErrInvalid)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkOpen(); err != nil {
		return err
	}
	err := c.deleteContext(linkIndex, incomingTEID)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (c *Controller) GetContext(linkIndex, incomingTEID uint32) (Context, error) {
	if linkIndex == 0 || incomingTEID == 0 {
		return Context{}, fmt.Errorf("%w: link index and incoming TEID are required", ErrInvalid)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkOpen(); err != nil {
		return Context{}, err
	}
	return c.getContext(linkIndex, incomingTEID)
}

func (c *Controller) ListContexts(linkIndex uint32) ([]Context, error) {
	if linkIndex == 0 {
		return nil, fmt.Errorf("%w: link index is required", ErrInvalid)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkOpen(); err != nil {
		return nil, err
	}
	return c.listContexts(linkIndex)
}

// Reconcile applies desired contexts before deleting stale contexts. Every
// successful mutation has a reverse operation; an error triggers best-effort
// rollback and stale deletion never starts until all desired state exists.
func (c *Controller) Reconcile(linkIndex uint32, rawDesired []Context) (ReconcileReport, error) {
	if linkIndex == 0 {
		return ReconcileReport{}, fmt.Errorf("%w: link index is required", ErrInvalid)
	}
	desired := make([]Context, len(rawDesired))
	byTEID := make(map[uint32]Context, len(rawDesired))
	byUE := make(map[netip.Addr]Context, len(rawDesired))
	for index, raw := range rawDesired {
		context, err := normalizeContext(raw)
		if err != nil {
			return ReconcileReport{}, fmt.Errorf("desired context %d: %w", index, err)
		}
		if context.LinkIndex != linkIndex {
			return ReconcileReport{}, fmt.Errorf("desired context %d: %w: wrong link index", index, ErrInvalid)
		}
		if _, exists := byTEID[context.IncomingTEID]; exists {
			return ReconcileReport{}, fmt.Errorf("desired context %d: %w: duplicate incoming TEID", index, ErrIdentityConflict)
		}
		if _, exists := byUE[context.UEIPv4]; exists {
			return ReconcileReport{}, fmt.Errorf("desired context %d: %w: duplicate UE address", index, ErrIdentityConflict)
		}
		desired[index] = context
		byTEID[context.IncomingTEID] = context
		byUE[context.UEIPv4] = context
	}
	sort.Slice(desired, func(i, j int) bool { return desired[i].IncomingTEID < desired[j].IncomingTEID })

	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkOpen(); err != nil {
		return ReconcileReport{}, err
	}
	existing, err := c.listContexts(linkIndex)
	if err != nil {
		return ReconcileReport{}, err
	}
	existingByTEID := make(map[uint32]Context, len(existing))
	existingByUE := make(map[netip.Addr]Context, len(existing))
	for _, context := range existing {
		existingByTEID[context.IncomingTEID] = context
		existingByUE[context.UEIPv4] = context
	}
	for _, context := range desired {
		if current, ok := existingByTEID[context.IncomingTEID]; ok && current.UEIPv4 != context.UEIPv4 {
			return ReconcileReport{}, fmt.Errorf("incoming TEID %d: %w", context.IncomingTEID, ErrIdentityConflict)
		}
		if current, ok := existingByUE[context.UEIPv4]; ok && current.IncomingTEID != context.IncomingTEID {
			return ReconcileReport{}, fmt.Errorf("UE %s: %w", context.UEIPv4, ErrIdentityConflict)
		}
	}

	type undoOperation func() error
	undos := make([]undoOperation, 0, len(existing)+len(desired))
	rollback := func(cause error) error {
		joined := cause
		for index := len(undos) - 1; index >= 0; index-- {
			if undoErr := undos[index](); undoErr != nil {
				joined = errors.Join(joined, fmt.Errorf("rollback operation %d: %w", index, undoErr))
			}
		}
		return joined
	}

	var report ReconcileReport
	for _, context := range desired {
		current, exists := existingByTEID[context.IncomingTEID]
		if !exists {
			if err := c.addContext(context, true); err != nil {
				return ReconcileReport{}, rollback(err)
			}
			candidate := context
			undos = append(undos, func() error { return c.deleteContext(candidate.LinkIndex, candidate.IncomingTEID) })
			report.Created++
			continue
		}
		if sameContext(current, context) {
			report.Unchanged++
			continue
		}
		if err := c.replaceContext(current, context); err != nil {
			return ReconcileReport{}, rollback(err)
		}
		previous := current
		replacement := context
		undos = append(undos, func() error { return c.replaceContext(replacement, previous) })
		report.Updated++
	}
	for _, current := range existing {
		if _, keep := byTEID[current.IncomingTEID]; keep {
			continue
		}
		if err := c.deleteContext(current.LinkIndex, current.IncomingTEID); err != nil {
			return ReconcileReport{}, rollback(err)
		}
		previous := current
		undos = append(undos, func() error { return c.addContext(previous, true) })
		report.Deleted++
	}
	return report, nil
}

func (c *Controller) checkOpen() error {
	if c.closed {
		return ErrClosed
	}
	return nil
}

func (c *Controller) addContext(context Context, exclusive bool) error {
	data, err := encodeContext(context, true)
	if err != nil {
		return err
	}
	flags := netlink.Request | netlink.Acknowledge
	if exclusive {
		flags |= netlink.Excl
	}
	_, err = c.generic.Execute(genetlink.Message{
		Header: genetlink.Header{Command: gtpCommandNewPDP, Version: gtpFamilyVersion}, Data: data,
	}, c.family, flags)
	if err != nil {
		return fmt.Errorf("install PDP link=%d itei=%d ue=%s: %w", context.LinkIndex, context.IncomingTEID, context.UEIPv4, err)
	}
	return nil
}

func (c *Controller) replaceContext(previous, next Context) error {
	if !sameIdentity(previous, next) {
		return fmt.Errorf("replace PDP context: %w", ErrIdentityConflict)
	}
	if err := c.deleteContext(previous.LinkIndex, previous.IncomingTEID); err != nil {
		return err
	}
	if err := c.addContext(next, true); err != nil {
		rollbackErr := c.addContext(previous, true)
		if rollbackErr != nil {
			return errors.Join(err, fmt.Errorf("restore previous PDP context: %w", rollbackErr))
		}
		return err
	}
	return nil
}

func (c *Controller) deleteContext(linkIndex, incomingTEID uint32) error {
	encoder := netlink.NewAttributeEncoder()
	encoder.Uint32(gtpAttributeVersion, gtpVersion1)
	encoder.Uint32(gtpAttributeLink, linkIndex)
	encoder.Uint32(gtpAttributeIncomingTEID, incomingTEID)
	data, err := encoder.Encode()
	if err != nil {
		return err
	}
	_, err = c.generic.Execute(genetlink.Message{
		Header: genetlink.Header{Command: gtpCommandDeletePDP, Version: gtpFamilyVersion}, Data: data,
	}, c.family, netlink.Request|netlink.Acknowledge)
	if err != nil {
		return fmt.Errorf("delete PDP link=%d itei=%d: %w", linkIndex, incomingTEID, err)
	}
	return nil
}

func (c *Controller) getContext(linkIndex, incomingTEID uint32) (Context, error) {
	encoder := netlink.NewAttributeEncoder()
	encoder.Uint32(gtpAttributeVersion, gtpVersion1)
	encoder.Uint32(gtpAttributeLink, linkIndex)
	encoder.Uint32(gtpAttributeIncomingTEID, incomingTEID)
	data, err := encoder.Encode()
	if err != nil {
		return Context{}, err
	}
	messages, err := c.generic.Execute(genetlink.Message{
		Header: genetlink.Header{Command: gtpCommandGetPDP, Version: gtpFamilyVersion}, Data: data,
	}, c.family, netlink.Request)
	if err != nil {
		return Context{}, fmt.Errorf("get PDP link=%d itei=%d: %w", linkIndex, incomingTEID, err)
	}
	if len(messages) != 1 {
		return Context{}, fmt.Errorf("get PDP link=%d itei=%d: expected one response, got %d", linkIndex, incomingTEID, len(messages))
	}
	context, supported, err := decodeContext(messages[0].Data)
	if err != nil {
		return Context{}, err
	}
	if !supported {
		return Context{}, fmt.Errorf("get PDP link=%d itei=%d: unsupported GTP version", linkIndex, incomingTEID)
	}
	return context, nil
}

func (c *Controller) listContexts(linkIndex uint32) ([]Context, error) {
	messages, err := c.generic.Execute(genetlink.Message{
		Header: genetlink.Header{Command: gtpCommandGetPDP, Version: gtpFamilyVersion},
	}, c.family, netlink.Request|netlink.Dump)
	if err != nil {
		return nil, fmt.Errorf("dump GTP PDP contexts: %w", err)
	}
	contexts := make([]Context, 0, len(messages))
	for index, message := range messages {
		context, supported, err := decodeContext(message.Data)
		if err != nil {
			return nil, fmt.Errorf("decode PDP dump entry %d: %w", index, err)
		}
		if supported && context.LinkIndex == linkIndex {
			contexts = append(contexts, context)
		}
	}
	sort.Slice(contexts, func(i, j int) bool { return contexts[i].IncomingTEID < contexts[j].IncomingTEID })
	return contexts, nil
}

func encodeContext(context Context, includePeer bool) ([]byte, error) {
	encoder := netlink.NewAttributeEncoder()
	encoder.Uint32(gtpAttributeVersion, gtpVersion1)
	encoder.Uint32(gtpAttributeLink, context.LinkIndex)
	if includePeer {
		peer := context.PeerIPv4.As4()
		ue := context.UEIPv4.As4()
		encoder.Bytes(gtpAttributePeerAddress, peer[:])
		encoder.Bytes(gtpAttributeMSAddress, ue[:])
		encoder.Uint32(gtpAttributeIncomingTEID, context.IncomingTEID)
		encoder.Uint32(gtpAttributeOutgoingTEID, context.OutgoingTEID)
	}
	return encoder.Encode()
}

func decodeContext(data []byte) (Context, bool, error) {
	decoder, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return Context{}, false, err
	}
	var context Context
	var version uint32
	var seenLink, seenVersion, seenPeer, seenUE, seenIncoming, seenOutgoing bool
	for decoder.Next() {
		switch decoder.Type() {
		case gtpAttributeLink:
			context.LinkIndex = decoder.Uint32()
			seenLink = true
		case gtpAttributeVersion:
			version = decoder.Uint32()
			seenVersion = true
		case gtpAttributePeerAddress:
			address, parseErr := ipv4FromBytes(decoder.Bytes())
			if parseErr != nil {
				return Context{}, false, fmt.Errorf("peer address: %w", parseErr)
			}
			context.PeerIPv4 = address
			seenPeer = true
		case gtpAttributeMSAddress:
			address, parseErr := ipv4FromBytes(decoder.Bytes())
			if parseErr != nil {
				return Context{}, false, fmt.Errorf("UE address: %w", parseErr)
			}
			context.UEIPv4 = address
			seenUE = true
		case gtpAttributeIncomingTEID:
			context.IncomingTEID = decoder.Uint32()
			seenIncoming = true
		case gtpAttributeOutgoingTEID:
			context.OutgoingTEID = decoder.Uint32()
			seenOutgoing = true
		}
	}
	if err := decoder.Err(); err != nil {
		return Context{}, false, err
	}
	if !seenVersion {
		return Context{}, false, errors.New("missing GTP version")
	}
	if version != gtpVersion1 {
		return Context{}, false, nil
	}
	if !seenLink || !seenPeer || !seenUE || !seenIncoming || !seenOutgoing {
		return Context{}, false, errors.New("incomplete GTPv1 PDP context")
	}
	context, err = normalizeContext(context)
	if err != nil {
		return Context{}, false, err
	}
	return context, true, nil
}

func encodeLinkAttributes(config LinkConfig, fd int, alias string) ([]byte, error) {
	encoder := netlink.NewAttributeEncoder()
	encoder.String(iflaIfName, config.Name)
	encoder.Uint32(iflaMTU, config.MTU)
	encoder.String(iflaIfAlias, alias)
	encoder.Nested(iflaLinkInfo, func(info *netlink.AttributeEncoder) error {
		info.String(iflaInfoKind, gtpFamilyName)
		info.Nested(iflaInfoData, func(data *netlink.AttributeEncoder) error {
			data.Uint32(iflaGTPFD1, uint32(fd))
			data.Uint32(iflaGTPPDPHashSize, config.HashSize)
			data.Uint32(iflaGTPRole, uint32(config.Role))
			data.Uint8(iflaGTPRestartCount, config.RestartCounter)
			return nil
		})
		return nil
	})
	return encoder.Encode()
}

func (c *Controller) inspectLink(index uint32) (Link, error) {
	request := netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(unix.RTM_GETLINK), Flags: netlink.Request},
		Data:   marshalIfInfo(unix.IfInfomsg{Family: unix.AF_UNSPEC, Index: int32(index)}),
	}
	messages, err := c.route.Execute(request)
	if err != nil {
		return Link{}, fmt.Errorf("inspect link index %d: %w", index, err)
	}
	if len(messages) != 1 || len(messages[0].Data) < unix.SizeofIfInfomsg {
		return Link{}, fmt.Errorf("inspect link index %d: malformed response", index)
	}
	decoder, err := netlink.NewAttributeDecoder(messages[0].Data[unix.SizeofIfInfomsg:])
	if err != nil {
		return Link{}, err
	}
	link := Link{Index: index}
	for decoder.Next() {
		switch decoder.Type() {
		case iflaIfName:
			link.Name = decoder.String()
		case iflaMTU:
			link.MTU = decoder.Uint32()
		case iflaIfAlias:
			link.Alias = decoder.String()
		case iflaLinkInfo:
			decoder.Nested(func(info *netlink.AttributeDecoder) error {
				for info.Next() {
					switch info.Type() {
					case iflaInfoKind:
						link.Kind = info.String()
					case iflaInfoData:
						info.Nested(func(data *netlink.AttributeDecoder) error {
							for data.Next() {
								switch data.Type() {
								case iflaGTPPDPHashSize:
									link.HashSize = data.Uint32()
								case iflaGTPRole:
									link.Role = Role(data.Uint32())
								case iflaGTPRestartCount:
									link.RestartCounter = data.Uint8()
								}
							}
							return data.Err()
						})
					}
				}
				return info.Err()
			})
		}
	}
	if err := decoder.Err(); err != nil {
		return Link{}, err
	}
	return link, nil
}

func (c *Controller) setLinkUp(index uint32) error {
	request := netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(unix.RTM_NEWLINK), Flags: netlink.Request | netlink.Acknowledge},
		Data: marshalIfInfo(unix.IfInfomsg{
			Family: unix.AF_UNSPEC, Index: int32(index), Flags: unix.IFF_UP, Change: unix.IFF_UP,
		}),
	}
	_, err := c.route.Execute(request)
	return err
}

func (c *Controller) setLinkAlias(index uint32, alias string) error {
	encoder := netlink.NewAttributeEncoder()
	encoder.String(iflaIfAlias, alias)
	attributes, err := encoder.Encode()
	if err != nil {
		return err
	}
	request := netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(unix.RTM_NEWLINK), Flags: netlink.Request | netlink.Acknowledge},
		Data:   append(marshalIfInfo(unix.IfInfomsg{Family: unix.AF_UNSPEC, Index: int32(index)}), attributes...),
	}
	_, err = c.route.Execute(request)
	return err
}

func (c *Controller) deleteLinkByIndex(index uint32) error {
	request := netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(unix.RTM_DELLINK), Flags: netlink.Request | netlink.Acknowledge},
		Data:   marshalIfInfo(unix.IfInfomsg{Family: unix.AF_UNSPEC, Index: int32(index)}),
	}
	if _, err := c.route.Execute(request); err != nil {
		return fmt.Errorf("delete GTP link index %d: %w", index, err)
	}
	return nil
}

func (c *Controller) addIPv4Address(index uint32, address netip.Addr) error {
	return c.changeIPv4Address(unix.RTM_NEWADDR, netlink.Request|netlink.Acknowledge|netlink.Create|netlink.Excl, index, address)
}

func (c *Controller) deleteIPv4Address(index uint32, address netip.Addr) error {
	return c.changeIPv4Address(unix.RTM_DELADDR, netlink.Request|netlink.Acknowledge, index, address)
}

func (c *Controller) changeIPv4Address(messageType uint16, flags netlink.HeaderFlags, index uint32, address netip.Addr) error {
	raw := address.As4()
	encoder := netlink.NewAttributeEncoder()
	encoder.Bytes(ifaAddress, raw[:])
	encoder.Bytes(ifaLocal, raw[:])
	attributes, err := encoder.Encode()
	if err != nil {
		return err
	}
	request := netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(messageType), Flags: flags},
		Data: append(marshalIfAddress(unix.IfAddrmsg{
			Family: unix.AF_INET, Prefixlen: 32, Scope: unix.RT_SCOPE_UNIVERSE, Index: index,
		}), attributes...),
	}
	_, err = c.route.Execute(request)
	return err
}

func (c *Controller) addIPv4Route(index uint32, prefix netip.Prefix) error {
	raw := prefix.Addr().As4()
	encoder := netlink.NewAttributeEncoder()
	encoder.Bytes(rtaDestination, raw[:])
	encoder.Uint32(rtaOutput, index)
	attributes, err := encoder.Encode()
	if err != nil {
		return err
	}
	request := netlink.Message{
		Header: netlink.Header{
			Type: netlink.HeaderType(unix.RTM_NEWROUTE), Flags: netlink.Request | netlink.Acknowledge | netlink.Create | netlink.Excl,
		},
		Data: append(marshalRoute(unix.RtMsg{
			Family: unix.AF_INET, Dst_len: uint8(prefix.Bits()), Table: unix.RT_TABLE_MAIN,
			Protocol: unix.RTPROT_STATIC, Scope: unix.RT_SCOPE_LINK, Type: unix.RTN_UNICAST,
		}), attributes...),
	}
	_, err = c.route.Execute(request)
	return err
}

func openGTPSocket(local netip.Addr, bufferBytes int) (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
	if err != nil {
		return -1, fmt.Errorf("create GTP-U socket: %w", err)
	}
	closeOnError := func(cause error) (int, error) {
		_ = unix.Close(fd)
		return -1, cause
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, bufferBytes); err != nil {
		return closeOnError(fmt.Errorf("set GTP-U receive buffer: %w", err))
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, bufferBytes); err != nil {
		return closeOnError(fmt.Errorf("set GTP-U send buffer: %w", err))
	}
	address := unix.SockaddrInet4{Port: int(GTPUPort), Addr: local.As4()}
	if err := unix.Bind(fd, &address); err != nil {
		return closeOnError(fmt.Errorf("bind kernel GTP-U socket on %s:%d: %w", local, GTPUPort, err))
	}
	return fd, nil
}

func marshalIfInfo(info unix.IfInfomsg) []byte {
	data := make([]byte, unix.SizeofIfInfomsg)
	data[0] = info.Family
	binary.NativeEndian.PutUint16(data[2:4], info.Type)
	binary.NativeEndian.PutUint32(data[4:8], uint32(info.Index))
	binary.NativeEndian.PutUint32(data[8:12], info.Flags)
	binary.NativeEndian.PutUint32(data[12:16], info.Change)
	return data
}

func marshalIfAddress(address unix.IfAddrmsg) []byte {
	data := make([]byte, unix.SizeofIfAddrmsg)
	data[0] = address.Family
	data[1] = address.Prefixlen
	data[2] = address.Flags
	data[3] = address.Scope
	binary.NativeEndian.PutUint32(data[4:8], address.Index)
	return data
}

func marshalRoute(route unix.RtMsg) []byte {
	data := make([]byte, unix.SizeofRtMsg)
	data[0] = route.Family
	data[1] = route.Dst_len
	data[2] = route.Src_len
	data[3] = route.Tos
	data[4] = route.Table
	data[5] = route.Protocol
	data[6] = route.Scope
	data[7] = route.Type
	binary.NativeEndian.PutUint32(data[8:12], route.Flags)
	return data
}

func ipv4FromBytes(data []byte) (netip.Addr, error) {
	if len(data) != 4 {
		return netip.Addr{}, fmt.Errorf("expected 4 bytes, got %d", len(data))
	}
	var raw [4]byte
	copy(raw[:], data)
	return netip.AddrFrom4(raw), nil
}

func stringTrim(value string) string {
	for len(value) > 0 {
		last := value[len(value)-1]
		if last != 0 && last != ' ' && last != '\t' && last != '\r' && last != '\n' {
			break
		}
		value = value[:len(value)-1]
	}
	return value
}

func findInterface(name string) (*net.Interface, bool, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, false, err
	}
	for index := range interfaces {
		if interfaces[index].Name == name {
			return &interfaces[index], true, nil
		}
	}
	return nil, false, nil
}
