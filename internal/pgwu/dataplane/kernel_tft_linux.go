//go:build linux

package dataplane

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"golang.org/x/sys/unix"

	"github.com/lodestarnetworks/cups/internal/pgwu/rules"
	"github.com/lodestarnetworks/cups/pkg/gtpv2"
)

const (
	kernelTFTTablePrefix      = "sgwn_q1_"
	kernelTFTPreroutingChain  = "qci1_prerouting"
	kernelTFTOutputChain      = "qci1_output"
	kernelTFTDispatchMap      = "ue_dispatch"
	kernelTFTOwnerPrefix      = "sgw-next:pgwu-qci1-tft:v1:"
	kernelTFTSessionChainRoot = "q_"
	kernelTFTReconcileBatch   = 256
)

type installedKernelTFT struct {
	upSEID    uint64
	revision  uint64
	ue        netip.Addr
	chainName string
	ruleCount uint64
	filters   []rules.FlowFilter
}

type kernelTFTClassifier struct {
	mu         sync.Mutex
	connection *nftables.Conn
	table      *nftables.Table
	prerouting *nftables.Chain
	output     *nftables.Chain
	dispatch   *nftables.Set
	tableName  string
	owner      string
	pools      []netip.Prefix
	mark       uint32
	mask       uint32
	maxSession uint32
	installed  map[uint64]installedKernelTFT
	closed     bool
	syncErrors uint64
}

type kernelTFTSnapshot struct {
	Sessions uint64
	Rules    uint64
	Errors   uint64
}

func openKernelTFTClassifier(config kernelPolicyConfig) (*kernelTFTClassifier, error) {
	pools, err := normalizeUEPoolPrefixes(config.UEPoolPrefixes, config.UEPoolPrefix)
	if err != nil {
		return nil, fmt.Errorf("pgwu kernel TFT: %w", err)
	}
	if config.FirewallMark == 0 || config.FirewallMask == 0 || config.FirewallMark&^config.FirewallMask != 0 {
		return nil, errors.New("pgwu kernel TFT: firewall mark must be non-zero and contained by its mask")
	}
	if config.MaxSessions <= 0 || uint64(config.MaxSessions) > uint64(^uint32(0)) {
		return nil, errors.New("pgwu kernel TFT: invalid session capacity")
	}
	token, ok := kernelTFTToken(config.QCI1Link.Alias)
	if !ok {
		return nil, errors.New("pgwu kernel TFT: QCI 1 link has no valid ownership token")
	}
	classifier := &kernelTFTClassifier{
		tableName: kernelTFTTablePrefix + config.QCI1Link.Name,
		owner:     kernelTFTOwnerPrefix + token, pools: pools,
		mark: config.FirewallMark, mask: config.FirewallMask,
		maxSession: uint32(config.MaxSessions), installed: make(map[uint64]installedKernelTFT),
	}
	connection, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("pgwu kernel TFT: open nftables: %w", err)
	}
	classifier.connection = connection
	existing, err := classifier.findTable(connection)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		if err := classifier.verifyOwnedTable(connection, existing); err != nil {
			return nil, fmt.Errorf("pgwu kernel TFT: refuse foreign table %q: %w", classifier.tableName, err)
		}
		connection.DelTable(existing)
		if err := connection.Flush(); err != nil {
			return nil, fmt.Errorf("pgwu kernel TFT: remove owned crash-leftover table %q: %w", classifier.tableName, err)
		}
	}
	if err := classifier.createTableLocked(); err != nil {
		return nil, err
	}
	return classifier, nil
}

func kernelTFTToken(alias string) (string, bool) {
	const prefix = "sgw-next:kernel-gtp:v2:"
	if !strings.HasPrefix(alias, prefix) {
		return "", false
	}
	token := strings.TrimPrefix(alias, prefix)
	if len(token) != 64 || token != strings.ToLower(token) {
		return "", false
	}
	for _, character := range token {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return "", false
		}
	}
	return token, true
}

func (c *kernelTFTClassifier) createTableLocked() error {
	connection, err := nftables.New()
	if err != nil {
		return fmt.Errorf("pgwu kernel TFT: open nftables: %w", err)
	}
	table := connection.CreateTable(&nftables.Table{Name: c.tableName, Family: nftables.TableFamilyIPv4})
	prerouting := connection.AddChain(&nftables.Chain{
		Name: kernelTFTPreroutingChain, Table: table, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityMangle,
	})
	output := connection.AddChain(&nftables.Chain{
		Name: kernelTFTOutputChain, Table: table, Type: nftables.ChainTypeRoute,
		Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityMangle,
	})
	dispatch := &nftables.Set{
		Table: table, Name: kernelTFTDispatchMap, IsMap: true,
		KeyType: nftables.TypeIPAddr, DataType: nftables.TypeVerdict,
		Size: c.maxSession, Comment: c.owner,
	}
	if err := connection.AddSet(dispatch, nil); err != nil {
		return fmt.Errorf("pgwu kernel TFT: create UE verdict map: %w", err)
	}
	for _, chain := range []*nftables.Chain{prerouting, output} {
		chainLabel := "prerouting"
		if chain == output {
			chainLabel = "output"
		}
		for index, pool := range c.pools {
			connection.AddRule(&nftables.Rule{
				Table: table, Chain: chain, Exprs: kernelTFTClearMarkExpressions(pool, c.mask),
				UserData: userdata.AppendString(nil, userdata.TypeComment,
					fmt.Sprintf("%s/base/clear/%s/%d", c.owner, chainLabel, index)),
			})
		}
		connection.AddRule(&nftables.Rule{
			Table: table, Chain: chain, Exprs: []expr.Any{
				&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4, DestRegister: 1},
				&expr.Lookup{SourceRegister: 1, SetName: dispatch.Name, SetID: dispatch.ID, DestRegister: 0, IsDestRegSet: true},
			},
			UserData: userdata.AppendString(nil, userdata.TypeComment, c.owner+"/base/dispatch/"+chainLabel),
		})
	}
	if err := connection.Flush(); err != nil {
		return fmt.Errorf("pgwu kernel TFT: install owned table %q: %w", c.tableName, err)
	}
	c.connection, c.table, c.prerouting, c.output, c.dispatch = connection, table, prerouting, output, dispatch
	if err := c.verifyOwnedTable(connection, table); err != nil {
		connection.DelTable(table)
		cleanupErr := connection.Flush()
		return errors.Join(fmt.Errorf("pgwu kernel TFT: verify table %q: %w", c.tableName, err), cleanupErr)
	}
	return nil
}

func kernelTFTClearMarkExpressions(pool netip.Prefix, mask uint32) []expr.Any {
	poolAddress := pool.Addr().As4()
	poolMask := net.CIDRMask(pool.Bits(), 32)
	maskedPool := [4]byte{}
	for index := range maskedPool {
		maskedPool[index] = poolAddress[index] & poolMask[index]
	}
	clearMask := make([]byte, 4)
	binary.NativeEndian.PutUint32(clearMask, ^mask)
	return []expr.Any{
		&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4, DestRegister: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: append([]byte(nil), poolMask...), Xor: []byte{0, 0, 0, 0}},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: maskedPool[:]},
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: clearMask, Xor: []byte{0, 0, 0, 0}},
		&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1},
	}
}

func (c *kernelTFTClassifier) Apply(previous, next *rules.Session) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("pgwu kernel TFT classifier is closed")
	}
	if previous != nil && next != nil && previous.UPSEID != next.UPSEID {
		return errors.New("pgwu kernel TFT: session identity changed")
	}
	var built *installedKernelTFT
	if next != nil && len(next.DedicatedBearers) != 0 {
		value, err := c.build(*next)
		if err != nil {
			return err
		}
		built = &value
	}
	upSEID := uint64(0)
	if previous != nil {
		upSEID = previous.UPSEID
	} else if next != nil {
		upSEID = next.UPSEID
	}
	old, hadOld := c.installed[upSEID]
	if !hadOld && built == nil {
		return nil
	}
	if hadOld && built != nil && old.revision == built.revision {
		return nil
	}
	if err := c.replaceLocked(old, hadOld, built); err != nil {
		c.syncErrors++
		return err
	}
	if built == nil {
		delete(c.installed, upSEID)
	} else {
		c.installed[built.upSEID] = *built
	}
	return nil
}

func (c *kernelTFTClassifier) replaceLocked(old installedKernelTFT, hadOld bool, next *installedKernelTFT) error {
	// Use a fresh batching connection for every transaction. If expression or
	// set-element encoding ever fails before Flush, discarding this object also
	// discards all queued mutations; a later transaction can never flush stale
	// partial work accidentally.
	connection, err := nftables.New()
	if err != nil {
		return fmt.Errorf("pgwu kernel TFT: open transaction: %w", err)
	}
	if next != nil {
		chain := connection.AddChain(&nftables.Chain{Name: next.chainName, Table: c.table})
		for index, filter := range next.filters {
			for expansion, expressions := range c.filterExpressions(next.ue, filter.Filter) {
				connection.AddRule(&nftables.Rule{
					Table: c.table, Chain: chain, Exprs: expressions,
					UserData: userdata.AppendString(nil, userdata.TypeComment,
						fmt.Sprintf("%s/session/%016x/%016x/filter/%d/%d", c.owner, next.upSEID, next.revision, index, expansion)),
				})
			}
		}
	}
	if hadOld {
		if err := connection.SetDeleteElements(c.dispatch, []nftables.SetElement{{Key: kernelTFTAddressKey(old.ue)}}); err != nil {
			return fmt.Errorf("pgwu kernel TFT: remove old UE dispatch: %w", err)
		}
		oldChain := &nftables.Chain{Name: old.chainName, Table: c.table}
		connection.FlushChain(oldChain)
		connection.DelChain(oldChain)
	}
	if next != nil {
		if err := connection.SetAddElements(c.dispatch, []nftables.SetElement{{
			Key:         kernelTFTAddressKey(next.ue),
			VerdictData: &expr.Verdict{Kind: expr.VerdictJump, Chain: next.chainName},
			Comment:     fmt.Sprintf("%s/session/%016x/%016x", c.owner, next.upSEID, next.revision),
		}}); err != nil {
			return fmt.Errorf("pgwu kernel TFT: install UE dispatch: %w", err)
		}
	}
	if err := connection.Flush(); err != nil {
		return fmt.Errorf("pgwu kernel TFT: atomically replace session route: %w", err)
	}
	return nil
}

func (c *kernelTFTClassifier) build(session rules.Session) (installedKernelTFT, error) {
	if session.UPSEID == 0 || session.Revision == 0 || !session.UEIPv4.Is4() || len(session.DedicatedBearers) != 1 {
		return installedKernelTFT{}, errors.New("pgwu kernel TFT: one valid QCI 1 bearer is required")
	}
	filters := make([]rules.FlowFilter, 0, len(session.DedicatedBearers[0].Filters))
	for _, filter := range session.DedicatedBearers[0].Filters {
		if filter.Direction != filter.Filter.Direction {
			return installedKernelTFT{}, errors.New("pgwu kernel TFT: inconsistent TFT direction metadata")
		}
		if filter.Filter.AppliesTo(gtpv2.TFTDirectionDownlink) {
			filters = append(filters, filter)
		}
	}
	if len(filters) == 0 || len(filters) > rules.MaxFiltersPerBearer {
		return installedKernelTFT{}, errors.New("pgwu kernel TFT: dedicated bearer needs 1-64 downlink filters")
	}
	sort.SliceStable(filters, func(i, j int) bool {
		if filters[i].Precedence != filters[j].Precedence {
			return filters[i].Precedence < filters[j].Precedence
		}
		return filters[i].PDRID < filters[j].PDRID
	})
	value := installedKernelTFT{
		upSEID: session.UPSEID, revision: session.Revision, ue: session.UEIPv4.Unmap(),
		chainName: fmt.Sprintf("%s%016x_%016x", kernelTFTSessionChainRoot, session.UPSEID, session.Revision),
		filters:   filters,
	}
	for _, filter := range filters {
		value.ruleCount += uint64(len(c.filterExpressions(value.ue, filter.Filter)))
	}
	return value, nil
}

func (c *kernelTFTClassifier) filterExpressions(ue netip.Addr, filter gtpv2.IPv4PacketFilter) [][]expr.Any {
	protocols := []uint8{filter.Protocol}
	if (filter.HasLocalPort || filter.HasRemotePort) && !filter.HasProtocol {
		protocols = []uint8{unix.IPPROTO_TCP, unix.IPPROTO_UDP, unix.IPPROTO_SCTP}
	} else if !filter.HasProtocol {
		protocols = []uint8{0}
	}
	out := make([][]expr.Any, 0, len(protocols))
	for _, protocol := range protocols {
		expressions := make([]expr.Any, 0, 20)
		expressions = append(expressions, kernelTFTMaskedPayload(16, ue, netip.MustParseAddr("255.255.255.255"))...)
		if filter.HasLocalAddress {
			expressions = append(expressions, kernelTFTMaskedPayload(16, filter.LocalAddress, filter.LocalAddressMask)...)
		}
		if filter.HasRemoteAddress {
			expressions = append(expressions, kernelTFTMaskedPayload(12, filter.RemoteAddress, filter.RemoteAddressMask)...)
		}
		if protocol != 0 {
			expressions = append(expressions,
				&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1, DestRegister: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protocol}},
			)
		}
		if filter.HasTypeOfService {
			expressions = append(expressions,
				&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: 1, Len: 1, DestRegister: 1},
				&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1, Mask: []byte{filter.TypeOfServiceMask}, Xor: []byte{0}},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{filter.TypeOfService & filter.TypeOfServiceMask}},
			)
		}
		if filter.HasRemotePort {
			expressions = append(expressions, kernelTFTPortExpressions(0, filter.RemotePortLow, filter.RemotePortHigh)...)
		}
		if filter.HasLocalPort {
			expressions = append(expressions, kernelTFTPortExpressions(2, filter.LocalPortLow, filter.LocalPortHigh)...)
		}
		markMask, markXor := make([]byte, 4), make([]byte, 4)
		// skb marks are host-endian metadata, unlike addresses and ports loaded
		// from the IPv4 packet. Encoding these constants in network order would
		// silently select a different FIB rule on little-endian gateways.
		binary.NativeEndian.PutUint32(markMask, ^c.mask)
		binary.NativeEndian.PutUint32(markXor, c.mark)
		expressions = append(expressions,
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: markMask, Xor: markXor},
			&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1},
			&expr.Verdict{Kind: expr.VerdictReturn},
		)
		out = append(out, expressions)
	}
	return out
}

func kernelTFTMaskedPayload(offset uint32, address, mask netip.Addr) []expr.Any {
	rawAddress, rawMask := address.Unmap().As4(), mask.Unmap().As4()
	masked := [4]byte{}
	for index := range masked {
		masked[index] = rawAddress[index] & rawMask[index]
	}
	return []expr.Any{
		&expr.Payload{Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: 4, DestRegister: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: rawMask[:], Xor: []byte{0, 0, 0, 0}},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: masked[:]},
	}
}

func kernelTFTPortExpressions(offset uint32, low, high uint16) []expr.Any {
	from, to := make([]byte, 2), make([]byte, 2)
	binary.BigEndian.PutUint16(from, low)
	binary.BigEndian.PutUint16(to, high)
	load := &expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: offset, Len: 2, DestRegister: 1}
	if low == high {
		return []expr.Any{load, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: from}}
	}
	return []expr.Any{load, &expr.Range{Op: expr.CmpOpEq, Register: 1, FromData: from, ToData: to}}
}

func kernelTFTAddressKey(address netip.Addr) []byte {
	raw := address.Unmap().As4()
	return append([]byte(nil), raw[:]...)
}

func (c *kernelTFTClassifier) Reconcile(sessions []rules.Session) error {
	desired := make([]installedKernelTFT, 0, len(sessions))
	seenUE := make(map[netip.Addr]struct{}, len(sessions))
	seenSEID := make(map[uint64]struct{}, len(sessions))
	for index := range sessions {
		if len(sessions[index].DedicatedBearers) == 0 {
			continue
		}
		built, err := c.build(sessions[index])
		if err != nil {
			return fmt.Errorf("pgwu kernel TFT reconcile session %d: %w", index, err)
		}
		if _, exists := seenUE[built.ue]; exists {
			return fmt.Errorf("pgwu kernel TFT reconcile: duplicate UE %s", built.ue)
		}
		if _, exists := seenSEID[built.upSEID]; exists {
			return fmt.Errorf("pgwu kernel TFT reconcile: duplicate UP-SEID %d", built.upSEID)
		}
		seenUE[built.ue], seenSEID[built.upSEID] = struct{}{}, struct{}{}
		desired = append(desired, built)
	}
	sort.Slice(desired, func(i, j int) bool { return desired[i].upSEID < desired[j].upSEID })

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("pgwu kernel TFT classifier is closed")
	}
	if err := c.resetLocked(); err != nil {
		c.syncErrors++
		return err
	}
	for start := 0; start < len(desired); start += kernelTFTReconcileBatch {
		end := min(start+kernelTFTReconcileBatch, len(desired))
		transaction, err := nftables.New()
		if err != nil {
			_ = c.resetLocked()
			c.syncErrors++
			return fmt.Errorf("pgwu kernel TFT reconcile: open transaction: %w", err)
		}
		for index := start; index < end; index++ {
			entry := desired[index]
			chain := transaction.AddChain(&nftables.Chain{Name: entry.chainName, Table: c.table})
			for filterIndex, filter := range entry.filters {
				for expansion, expressions := range c.filterExpressions(entry.ue, filter.Filter) {
					transaction.AddRule(&nftables.Rule{
						Table: c.table, Chain: chain, Exprs: expressions,
						UserData: userdata.AppendString(nil, userdata.TypeComment,
							fmt.Sprintf("%s/session/%016x/%016x/filter/%d/%d", c.owner, entry.upSEID, entry.revision, filterIndex, expansion)),
					})
				}
			}
			if err := transaction.SetAddElements(c.dispatch, []nftables.SetElement{{
				Key:         kernelTFTAddressKey(entry.ue),
				VerdictData: &expr.Verdict{Kind: expr.VerdictJump, Chain: entry.chainName},
				Comment:     fmt.Sprintf("%s/session/%016x/%016x", c.owner, entry.upSEID, entry.revision),
			}}); err != nil {
				_ = c.resetLocked()
				c.syncErrors++
				return err
			}
		}
		if err := transaction.Flush(); err != nil {
			_ = c.resetLocked()
			c.syncErrors++
			return fmt.Errorf("pgwu kernel TFT reconcile batch %d-%d: %w", start, end, err)
		}
	}
	c.installed = make(map[uint64]installedKernelTFT, len(desired))
	for _, entry := range desired {
		c.installed[entry.upSEID] = entry
	}
	return nil
}

func (c *kernelTFTClassifier) resetLocked() error {
	if c.table != nil {
		if err := c.verifyOwnedTable(c.connection, c.table); err != nil {
			return err
		}
		c.connection.DelTable(c.table)
		if err := c.connection.Flush(); err != nil {
			return fmt.Errorf("pgwu kernel TFT: reset table: %w", err)
		}
	}
	c.table, c.prerouting, c.output, c.dispatch = nil, nil, nil, nil
	c.installed = make(map[uint64]installedKernelTFT)
	return c.createTableLocked()
}

func (c *kernelTFTClassifier) Snapshot() kernelTFTSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	snapshot := kernelTFTSnapshot{Sessions: uint64(len(c.installed)), Errors: c.syncErrors}
	for _, entry := range c.installed {
		snapshot.Rules += entry.ruleCount
	}
	return snapshot
}

func (c *kernelTFTClassifier) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.table == nil {
		return nil
	}
	if err := c.verifyOwnedTable(c.connection, c.table); err != nil {
		return fmt.Errorf("pgwu kernel TFT: refuse to delete modified table %q: %w", c.tableName, err)
	}
	c.connection.DelTable(c.table)
	if err := c.connection.Flush(); err != nil {
		return fmt.Errorf("pgwu kernel TFT: remove table %q: %w", c.tableName, err)
	}
	c.table = nil
	return nil
}

func (c *kernelTFTClassifier) findTable(connection *nftables.Conn) (*nftables.Table, error) {
	tables, err := connection.ListTablesOfFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return nil, fmt.Errorf("pgwu kernel TFT: list IPv4 tables: %w", err)
	}
	for _, table := range tables {
		if table.Name == c.tableName {
			return table, nil
		}
	}
	return nil, nil
}

func (c *kernelTFTClassifier) verifyOwnedTable(connection *nftables.Conn, table *nftables.Table) error {
	if table == nil || table.Name != c.tableName || table.Family != nftables.TableFamilyIPv4 {
		return errors.New("unexpected nftables table identity")
	}
	chains, err := connection.ListChainsOfTableFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return err
	}
	matching := make([]*nftables.Chain, 0)
	for _, chain := range chains {
		if chain.Table != nil && chain.Table.Name == table.Name {
			matching = append(matching, chain)
		}
	}
	if len(matching) < 2 {
		return fmt.Errorf("owned table has %d chains, want at least 2", len(matching))
	}
	baseSeen := map[string]bool{kernelTFTPreroutingChain: false, kernelTFTOutputChain: false}
	for _, chain := range matching {
		switch chain.Name {
		case kernelTFTPreroutingChain:
			if chain.Type != nftables.ChainTypeFilter || chain.Hooknum == nil || *chain.Hooknum != *nftables.ChainHookPrerouting ||
				chain.Priority == nil || *chain.Priority != *nftables.ChainPriorityMangle {
				return errors.New("unexpected QCI 1 prerouting-chain metadata")
			}
			baseSeen[chain.Name] = true
		case kernelTFTOutputChain:
			if chain.Type != nftables.ChainTypeRoute || chain.Hooknum == nil || *chain.Hooknum != *nftables.ChainHookOutput ||
				chain.Priority == nil || *chain.Priority != *nftables.ChainPriorityMangle {
				return errors.New("unexpected QCI 1 output-chain metadata")
			}
			baseSeen[chain.Name] = true
		default:
			if !strings.HasPrefix(chain.Name, kernelTFTSessionChainRoot) || chain.Hooknum != nil || chain.Priority != nil {
				return fmt.Errorf("unexpected dynamic chain %q", chain.Name)
			}
		}
		ruleList, err := connection.GetRules(table, chain)
		if err != nil {
			return err
		}
		if chain.Name == kernelTFTPreroutingChain || chain.Name == kernelTFTOutputChain {
			wanted := len(c.pools) + 1
			if len(ruleList) != wanted {
				return fmt.Errorf("base chain %q has %d rules, want %d", chain.Name, len(ruleList), wanted)
			}
		} else if len(ruleList) == 0 {
			return fmt.Errorf("dynamic chain %q has no rules", chain.Name)
		}
		for _, rule := range ruleList {
			comment, ok := userdata.GetString(rule.UserData, userdata.TypeComment)
			if !ok || !strings.HasPrefix(comment, c.owner+"/") {
				return fmt.Errorf("chain %q contains a foreign rule", chain.Name)
			}
		}
	}
	if !baseSeen[kernelTFTPreroutingChain] || !baseSeen[kernelTFTOutputChain] {
		return errors.New("owned table is missing a base chain")
	}
	sets, err := connection.GetSets(table)
	if err != nil {
		return err
	}
	// nftables v0.3 decodes verdict-map key/data types in reverse on this
	// kernel. The table-owned lookup rule and every element's owner comment are
	// the deletion fence; verify the stable map identity here without trusting
	// those misdecoded datatype fields.
	if len(sets) != 1 || sets[0].Name != kernelTFTDispatchMap || !sets[0].IsMap {
		if len(sets) != 1 {
			return fmt.Errorf("owned table has %d sets, want 1", len(sets))
		}
		return fmt.Errorf("owned table has unexpected UE verdict-map metadata name=%q map=%v key=%q data=%q",
			sets[0].Name, sets[0].IsMap, sets[0].KeyType.Name, sets[0].DataType.Name)
	}
	elements, err := connection.GetSetElements(sets[0])
	if err != nil {
		return err
	}
	for _, element := range elements {
		if !strings.HasPrefix(element.Comment, c.owner+"/") {
			return errors.New("UE verdict map contains a foreign element")
		}
	}
	return nil
}
