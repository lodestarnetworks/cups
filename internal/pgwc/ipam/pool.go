// Package ipam provides bounded, concurrency-safe IPv4 address allocation for
// LTE PDN sessions. It deliberately owns no Linux routing state.
package ipam

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
)

var (
	ErrExhausted = errors.New("pgwc ipam: address pool exhausted")
	ErrNotFound  = errors.New("pgwc ipam: lease not found")
	ErrConflict  = errors.New("pgwc ipam: duplicate or conflicting recovered lease")
)

const maxPoolAddresses = 1 << 24

type Lease struct {
	Owner string
	Addr  netip.Addr
}

type Pool struct {
	mu      sync.Mutex
	prefix  netip.Prefix
	base    uint32
	size    uint32
	gateway uint32
	limit   int
	used    int
	cursor  uint32
	bitmap  []uint64
	byOwner map[string]uint32
	ownerBy map[uint32]string
}

func New(prefix netip.Prefix, gateway netip.Addr, maxLeases int) (*Pool, error) {
	if !prefix.IsValid() || !prefix.Addr().Is4() || prefix.Bits() < 8 || prefix.Bits() > 30 {
		return nil, errors.New("pgwc ipam: an IPv4 prefix between /8 and /30 is required")
	}
	prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()).Masked()
	if !gateway.Is4() || !prefix.Contains(gateway.Unmap()) {
		return nil, errors.New("pgwc ipam: gateway must be inside the pool prefix")
	}
	size64 := uint64(1) << uint64(32-prefix.Bits())
	if size64 > maxPoolAddresses {
		return nil, fmt.Errorf("pgwc ipam: pool has %d addresses; maximum is %d", size64, maxPoolAddresses)
	}
	size := uint32(size64)
	base := ipv4Uint32(prefix.Addr())
	gatewayOffset := ipv4Uint32(gateway.Unmap()) - base
	if gatewayOffset == 0 || gatewayOffset == size-1 {
		return nil, errors.New("pgwc ipam: gateway cannot be the network or broadcast address")
	}
	capacity := int(size) - 3 // network, broadcast, gateway
	if maxLeases < 0 {
		return nil, errors.New("pgwc ipam: max leases cannot be negative")
	}
	if maxLeases == 0 || maxLeases > capacity {
		maxLeases = capacity
	}
	p := &Pool{
		prefix: prefix, base: base, size: size, gateway: gatewayOffset,
		limit: maxLeases, cursor: 1, bitmap: make([]uint64, (size+63)/64),
		byOwner: make(map[string]uint32), ownerBy: make(map[uint32]string),
	}
	p.mark(0, true)
	p.mark(size-1, true)
	p.mark(gatewayOffset, true)
	return p, nil
}

func (p *Pool) Acquire(owner string) (Lease, error) {
	if owner == "" {
		return Lease{}, errors.New("pgwc ipam: lease owner is required")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if offset, ok := p.byOwner[owner]; ok {
		return Lease{Owner: owner, Addr: p.addr(offset)}, nil
	}
	if p.used >= p.limit {
		return Lease{}, ErrExhausted
	}
	for checked := uint32(0); checked < p.size; checked++ {
		offset := p.cursor
		p.cursor++
		if p.cursor >= p.size-1 {
			p.cursor = 1
		}
		if p.marked(offset) {
			continue
		}
		p.mark(offset, true)
		p.byOwner[owner] = offset
		p.ownerBy[offset] = owner
		p.used++
		return Lease{Owner: owner, Addr: p.addr(offset)}, nil
	}
	return Lease{}, ErrExhausted
}

func (p *Pool) Release(owner string, addr netip.Addr) error {
	if owner == "" || !addr.Is4() {
		return ErrNotFound
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	offset, ok := p.byOwner[owner]
	if !ok || p.addr(offset) != addr.Unmap() {
		return ErrNotFound
	}
	delete(p.byOwner, owner)
	delete(p.ownerBy, offset)
	p.mark(offset, false)
	p.used--
	if offset < p.cursor {
		p.cursor = offset
	}
	return nil
}

func (p *Pool) Find(owner string) (Lease, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	offset, ok := p.byOwner[owner]
	if !ok {
		return Lease{}, false
	}
	return Lease{Owner: owner, Addr: p.addr(offset)}, true
}

func (p *Pool) Snapshot() []Lease {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Lease, 0, len(p.ownerBy))
	for offset := uint32(1); offset < p.size-1; offset++ {
		if owner, ok := p.ownerBy[offset]; ok {
			out = append(out, Lease{Owner: owner, Addr: p.addr(offset)})
		}
	}
	return out
}

// Restore atomically reserves exact addresses from durable PGW-C session
// state. The pool must be empty and every address must belong to this pool.
func (p *Pool) Restore(leases []Lease) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.used != 0 || len(p.byOwner) != 0 || len(p.ownerBy) != 0 {
		return fmt.Errorf("%w: restore requires an empty pool", ErrConflict)
	}
	if len(leases) > p.limit {
		return ErrExhausted
	}
	bitmap := make([]uint64, len(p.bitmap))
	mark := func(offset uint32) { bitmap[offset/64] |= uint64(1) << (offset % 64) }
	marked := func(offset uint32) bool { return bitmap[offset/64]&(uint64(1)<<(offset%64)) != 0 }
	mark(0)
	mark(p.size - 1)
	mark(p.gateway)
	byOwner := make(map[string]uint32, len(leases))
	ownerBy := make(map[uint32]string, len(leases))
	for index, lease := range leases {
		address := lease.Addr.Unmap()
		if lease.Owner == "" || !address.Is4() || !p.prefix.Contains(address) {
			return fmt.Errorf("%w: invalid recovered lease %d", ErrConflict, index)
		}
		offset := ipv4Uint32(address) - p.base
		if offset >= p.size || marked(offset) {
			return fmt.Errorf("%w: unavailable recovered address %s", ErrConflict, address)
		}
		if _, exists := byOwner[lease.Owner]; exists {
			return fmt.Errorf("%w: duplicate recovered owner", ErrConflict)
		}
		mark(offset)
		byOwner[lease.Owner] = offset
		ownerBy[offset] = lease.Owner
	}
	cursor := uint32(1)
	for cursor < p.size-1 && marked(cursor) {
		cursor++
	}
	if cursor >= p.size-1 {
		cursor = 1
	}
	p.bitmap, p.byOwner, p.ownerBy = bitmap, byOwner, ownerBy
	p.used = len(leases)
	p.cursor = cursor
	return nil
}

func (p *Pool) Prefix() netip.Prefix { return p.prefix }
func (p *Pool) Capacity() int        { return p.limit }

func (p *Pool) Used() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.used
}

func (p *Pool) marked(offset uint32) bool {
	return p.bitmap[offset/64]&(uint64(1)<<(offset%64)) != 0
}

func (p *Pool) mark(offset uint32, value bool) {
	mask := uint64(1) << (offset % 64)
	if value {
		p.bitmap[offset/64] |= mask
	} else {
		p.bitmap[offset/64] &^= mask
	}
}

func (p *Pool) addr(offset uint32) netip.Addr {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], p.base+offset)
	return netip.AddrFrom4(raw)
}

func ipv4Uint32(addr netip.Addr) uint32 {
	raw := addr.Unmap().As4()
	return binary.BigEndian.Uint32(raw[:])
}
