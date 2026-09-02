//go:build linux

package kernelgtp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"golang.org/x/sys/unix"
)

const (
	peerFirewallTablePrefix = "sgwn_"
	peerFirewallChainName   = "gtpu_input"
	peerFirewallSetName     = "allowed_peers"
	peerFirewallOwnerPrefix = "sgw-next:kernel-gtp-firewall:v1:"
)

// peerFirewall is a process-owned nftables table that admits GTP-U only from
// configured outer peers. It runs at the IPv4 input hook, before UDP hands an
// skb to the kernel GTP tunnel callback. Accepting here does not bypass any
// later host firewall chain; dropping an untrusted peer is final.
type peerFirewall struct {
	tableName string
	owner     string
	closed    bool
}

func createPeerFirewall(linkName string, local netip.Addr, peers []netip.Addr, owner string) (*peerFirewall, error) {
	if !validPeerFirewallOwner(owner) {
		return nil, fmt.Errorf("%w: invalid GTP-U peer-filter owner", ErrInvalid)
	}
	tableName := peerFirewallTablePrefix + linkName
	connection, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("open nftables for GTP-U peer filter: %w", err)
	}
	exists, err := nftTableExists(connection, tableName)
	if err != nil {
		return nil, fmt.Errorf("check GTP-U peer-filter table %q: %w", tableName, err)
	}
	if exists {
		return nil, fmt.Errorf("create GTP-U peer-filter table %q: %w", tableName, ErrNotOwned)
	}

	table := connection.CreateTable(&nftables.Table{Name: tableName, Family: nftables.TableFamilyIPv4})
	policy := nftables.ChainPolicyAccept
	chain := connection.AddChain(&nftables.Chain{
		Name: peerFirewallChainName, Table: table, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityRaw, Policy: &policy,
	})
	set := &nftables.Set{
		Table: table, Name: peerFirewallSetName, KeyType: nftables.TypeIPAddr,
		Constant: true, Comment: owner,
	}
	elements := make([]nftables.SetElement, 0, len(peers))
	for _, peer := range peers {
		raw := peer.As4()
		elements = append(elements, nftables.SetElement{Key: append([]byte(nil), raw[:]...)})
	}
	if err := connection.AddSet(set, elements); err != nil {
		return nil, fmt.Errorf("encode GTP-U peer allowlist: %w", err)
	}

	allowExpressions := append(gtpuDestinationExpressions(local),
		&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4, DestRegister: 1},
		&expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID},
		&expr.Counter{},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)
	connection.AddRule(&nftables.Rule{
		Table: table, Chain: chain, Exprs: allowExpressions,
		UserData: userdata.AppendString(nil, userdata.TypeComment, owner+"/allow"),
	})
	dropExpressions := append(gtpuDestinationExpressions(local),
		&expr.Counter{},
		&expr.Verdict{Kind: expr.VerdictDrop},
	)
	connection.AddRule(&nftables.Rule{
		Table: table, Chain: chain, Exprs: dropExpressions,
		UserData: userdata.AppendString(nil, userdata.TypeComment, owner+"/drop"),
	})
	if err := connection.Flush(); err != nil {
		return nil, fmt.Errorf("install GTP-U peer filter %q: %w", tableName, err)
	}
	filter := &peerFirewall{tableName: tableName, owner: owner}
	verified, err := findOwnedPeerFirewall(connection, tableName, owner)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("verify installed GTP-U peer filter %q: %w", tableName, err), filter.Close())
	}
	if verified == nil {
		return nil, errors.Join(fmt.Errorf("verify installed GTP-U peer filter %q: %w", tableName, ErrNotOwned), filter.Close())
	}
	return filter, nil
}

func gtpuDestinationExpressions(local netip.Addr) []expr.Any {
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, GTPUPort)
	destination := local.As4()
	return []expr.Any{
		&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4, DestRegister: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: destination[:]},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
		&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2, DestRegister: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: port},
	}
}

func validPeerFirewallOwner(owner string) bool {
	if len(owner) <= len(peerFirewallOwnerPrefix) || owner[:len(peerFirewallOwnerPrefix)] != peerFirewallOwnerPrefix {
		return false
	}
	return validOwnerToken(owner[len(peerFirewallOwnerPrefix):])
}

// Close removes only a table whose rule-level ownership token still matches
// this process. If another administrator replaced the table, it is untouched.
func (f *peerFirewall) Close() error {
	if f == nil || f.closed {
		return nil
	}
	connection, err := nftables.New()
	if err != nil {
		return fmt.Errorf("open nftables to remove GTP-U peer filter: %w", err)
	}
	table, err := findNFTTable(connection, f.tableName)
	if err != nil {
		return fmt.Errorf("find GTP-U peer-filter table %q: %w", f.tableName, err)
	}
	if table == nil {
		f.closed = true
		return nil
	}
	owned, err := findOwnedPeerFirewall(connection, f.tableName, f.owner)
	if err != nil {
		return fmt.Errorf("verify GTP-U peer-filter ownership for %q: %w", f.tableName, err)
	}
	if owned == nil {
		return fmt.Errorf("remove GTP-U peer-filter table %q: %w", f.tableName, ErrNotOwned)
	}
	connection.DelTable(table)
	if err := connection.Flush(); err != nil {
		return fmt.Errorf("remove GTP-U peer-filter table %q: %w", f.tableName, err)
	}
	f.closed = true
	return nil
}

func (f *peerFirewall) Counters() (PeerFilterCounters, error) {
	if f == nil || f.closed {
		return PeerFilterCounters{}, ErrClosed
	}
	connection, err := nftables.New()
	if err != nil {
		return PeerFilterCounters{}, fmt.Errorf("open nftables to read GTP-U peer-filter counters: %w", err)
	}
	table, err := findNFTTable(connection, f.tableName)
	if err != nil {
		return PeerFilterCounters{}, fmt.Errorf("find GTP-U peer-filter table %q: %w", f.tableName, err)
	}
	if table == nil {
		return PeerFilterCounters{}, fmt.Errorf("read GTP-U peer-filter table %q: %w", f.tableName, ErrNotOwned)
	}
	owned, err := findOwnedPeerFirewall(connection, f.tableName, f.owner)
	if err != nil {
		return PeerFilterCounters{}, fmt.Errorf("verify GTP-U peer-filter ownership for %q: %w", f.tableName, err)
	}
	if owned == nil {
		return PeerFilterCounters{}, fmt.Errorf("read GTP-U peer-filter table %q: %w", f.tableName, ErrNotOwned)
	}
	rules, err := connection.GetRules(table, &nftables.Chain{Name: peerFirewallChainName, Table: table})
	if err != nil {
		return PeerFilterCounters{}, fmt.Errorf("read GTP-U peer-filter counters for %q: %w", f.tableName, err)
	}
	var counters PeerFilterCounters
	var foundAllow, foundDrop bool
	for _, rule := range rules {
		comment, ok := userdata.GetString(rule.UserData, userdata.TypeComment)
		if !ok || comment != f.owner+"/allow" && comment != f.owner+"/drop" {
			continue
		}
		for _, expression := range rule.Exprs {
			counter, ok := expression.(*expr.Counter)
			if !ok {
				continue
			}
			if comment == f.owner+"/allow" {
				counters.AllowedPackets, counters.AllowedBytes = counter.Packets, counter.Bytes
				foundAllow = true
			} else {
				counters.DroppedPackets, counters.DroppedBytes = counter.Packets, counter.Bytes
				foundDrop = true
			}
		}
	}
	if !foundAllow || !foundDrop {
		return PeerFilterCounters{}, fmt.Errorf("read GTP-U peer-filter counters for %q: %w", f.tableName, ErrNotOwned)
	}
	return counters, nil
}

// inspectOwnedPeerFirewall returns an existing table only after every object in
// it matches the durable owner token. A missing table is not an error; any
// partial, modified, or foreign table fails closed and is never deleted.
func inspectOwnedPeerFirewall(linkName, owner string) (*peerFirewall, bool, error) {
	tableName := peerFirewallTablePrefix + linkName
	connection, err := nftables.New()
	if err != nil {
		return nil, false, fmt.Errorf("open nftables to inspect GTP-U peer filter: %w", err)
	}
	table, err := findNFTTable(connection, tableName)
	if err != nil {
		return nil, false, fmt.Errorf("find GTP-U peer-filter table %q: %w", tableName, err)
	}
	if table == nil {
		return nil, false, nil
	}
	owned, err := findOwnedPeerFirewall(connection, tableName, owner)
	if err != nil {
		return nil, true, err
	}
	if owned == nil {
		return nil, true, fmt.Errorf("inspect GTP-U peer-filter table %q: %w", tableName, ErrNotOwned)
	}
	return owned, true, nil
}

func findOwnedPeerFirewall(connection *nftables.Conn, tableName, owner string) (*peerFirewall, error) {
	if !validPeerFirewallOwner(owner) {
		return nil, fmt.Errorf("%w: invalid GTP-U peer-filter owner", ErrInvalid)
	}
	table, err := findNFTTable(connection, tableName)
	if err != nil || table == nil {
		return nil, err
	}
	if table.Family != nftables.TableFamilyIPv4 {
		return nil, fmt.Errorf("%w: table %q has unexpected family %d", ErrNotOwned, tableName, table.Family)
	}

	chains, err := connection.ListChainsOfTableFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return nil, err
	}
	matchingChains := 0
	for _, chain := range chains {
		if chain.Table == nil || chain.Table.Name != tableName {
			continue
		}
		matchingChains++
		if chain.Name != peerFirewallChainName || chain.Type != nftables.ChainTypeFilter || chain.Hooknum == nil ||
			*chain.Hooknum != *nftables.ChainHookInput || chain.Priority == nil || *chain.Priority != *nftables.ChainPriorityRaw {
			return nil, fmt.Errorf("%w: table %q has unexpected chain metadata name=%q type=%q hook=%v priority=%v",
				ErrNotOwned, tableName, chain.Name, chain.Type, chain.Hooknum, chain.Priority)
		}
	}
	if matchingChains != 1 {
		return nil, fmt.Errorf("%w: table %q has %d chains, want 1", ErrNotOwned, tableName, matchingChains)
	}

	sets, err := connection.GetSets(table)
	if err != nil {
		return nil, err
	}
	// Linux preserves the set comment (visible through nft), but nftables v0.3
	// does not decode it on GetSets. The two rule userdata tokens below remain
	// the cryptographic ownership proof; here we verify the complete set shape.
	if len(sets) != 1 || sets[0].Name != peerFirewallSetName || !sets[0].Constant {
		if len(sets) != 1 {
			return nil, fmt.Errorf("%w: table %q has %d sets, want 1", ErrNotOwned, tableName, len(sets))
		}
		return nil, fmt.Errorf("%w: table %q has unexpected allowed-peer set metadata name=%q constant=%v",
			ErrNotOwned, tableName, sets[0].Name, sets[0].Constant)
	}

	rules, err := connection.GetRules(table, &nftables.Chain{Name: peerFirewallChainName, Table: table})
	if err != nil {
		return nil, err
	}
	if len(rules) != 2 {
		return nil, fmt.Errorf("%w: table %q has %d rules, want 2", ErrNotOwned, tableName, len(rules))
	}
	wanted := map[string]bool{owner + "/allow": false, owner + "/drop": false}
	for _, rule := range rules {
		comment, ok := userdata.GetString(rule.UserData, userdata.TypeComment)
		if !ok {
			return nil, fmt.Errorf("%w: table %q contains an unmarked rule", ErrNotOwned, tableName)
		}
		seen, expected := wanted[comment]
		if !expected || seen {
			return nil, fmt.Errorf("%w: table %q contains an unexpected or duplicate rule marker", ErrNotOwned, tableName)
		}
		wanted[comment] = true
	}
	if !wanted[owner+"/allow"] || !wanted[owner+"/drop"] {
		return nil, fmt.Errorf("%w: table %q is missing an owned rule", ErrNotOwned, tableName)
	}
	return &peerFirewall{tableName: tableName, owner: owner}, nil
}

func nftTableExists(connection *nftables.Conn, name string) (bool, error) {
	table, err := findNFTTable(connection, name)
	return table != nil, err
}

func findNFTTable(connection *nftables.Conn, name string) (*nftables.Table, error) {
	tables, err := connection.ListTablesOfFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return nil, err
	}
	for _, table := range tables {
		if table.Name == name {
			return table, nil
		}
	}
	return nil, nil
}
