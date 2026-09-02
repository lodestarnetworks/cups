package ipam

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
)

func TestPoolAllocationExhaustionAndReuse(t *testing.T) {
	pool, err := New(netip.MustParsePrefix("10.90.0.0/29"), netip.MustParseAddr("10.90.0.1"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if pool.Capacity() != 5 {
		t.Fatalf("capacity = %d, want 5", pool.Capacity())
	}
	seen := make(map[netip.Addr]struct{})
	for index := 0; index < pool.Capacity(); index++ {
		lease, err := pool.Acquire(fmt.Sprintf("owner-%d", index))
		if err != nil {
			t.Fatal(err)
		}
		if lease.Addr == netip.MustParseAddr("10.90.0.1") {
			t.Fatal("allocated gateway address")
		}
		if _, duplicate := seen[lease.Addr]; duplicate {
			t.Fatalf("duplicate address %s", lease.Addr)
		}
		seen[lease.Addr] = struct{}{}
	}
	if _, err := pool.Acquire("overflow"); !errors.Is(err, ErrExhausted) {
		t.Fatalf("overflow error = %v", err)
	}
	lease, _ := pool.Find("owner-2")
	if err := pool.Release("owner-2", lease.Addr); err != nil {
		t.Fatal(err)
	}
	reused, err := pool.Acquire("replacement")
	if err != nil || reused.Addr != lease.Addr {
		t.Fatalf("reused lease = %#v, %v; want %s", reused, err, lease.Addr)
	}
}

func TestPoolAcquireIsIdempotentAndConcurrent(t *testing.T) {
	pool, err := New(netip.MustParsePrefix("10.91.0.0/24"), netip.MustParseAddr("10.91.0.1"), 100)
	if err != nil {
		t.Fatal(err)
	}
	const workers = 64
	addresses := make(chan netip.Addr, workers)
	var group sync.WaitGroup
	for index := 0; index < workers; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			lease, err := pool.Acquire(fmt.Sprintf("imsi-%d", index))
			if err != nil {
				t.Errorf("acquire: %v", err)
				return
			}
			addresses <- lease.Addr
		}(index)
	}
	group.Wait()
	close(addresses)
	seen := make(map[netip.Addr]struct{})
	for addr := range addresses {
		if _, ok := seen[addr]; ok {
			t.Fatalf("duplicate address %s", addr)
		}
		seen[addr] = struct{}{}
	}
	first, _ := pool.Acquire("imsi-1")
	second, _ := pool.Acquire("imsi-1")
	if first != second || pool.Used() != workers {
		t.Fatalf("idempotent lease mismatch: %#v %#v used=%d", first, second, pool.Used())
	}
}

func TestPoolValidation(t *testing.T) {
	for _, test := range []struct {
		prefix  string
		gateway string
	}{
		{"10.0.0.0/7", "10.0.0.1"},
		{"10.0.0.0/31", "10.0.0.1"},
		{"10.0.0.0/24", "10.0.1.1"},
		{"10.0.0.0/24", "10.0.0.0"},
	} {
		if _, err := New(netip.MustParsePrefix(test.prefix), netip.MustParseAddr(test.gateway), 0); err == nil {
			t.Fatalf("accepted prefix=%s gateway=%s", test.prefix, test.gateway)
		}
	}
}

func TestPoolRestoresExactDurableLeases(t *testing.T) {
	pool, err := New(netip.MustParsePrefix("10.92.0.0/29"), netip.MustParseAddr("10.92.0.1"), 5)
	if err != nil {
		t.Fatal(err)
	}
	leases := []Lease{
		{Owner: "subscriber-a\x00lodestartest", Addr: netip.MustParseAddr("10.92.0.4")},
		{Owner: "subscriber-b\x00lodestartest", Addr: netip.MustParseAddr("10.92.0.6")},
	}
	if err := pool.Restore(leases); err != nil {
		t.Fatal(err)
	}
	if pool.Used() != 2 {
		t.Fatalf("restored lease count = %d", pool.Used())
	}
	for _, want := range leases {
		got, ok := pool.Find(want.Owner)
		if !ok || got != want {
			t.Fatalf("restored lease = %+v, %v; want %+v", got, ok, want)
		}
	}
	allocated, err := pool.Acquire("subscriber-c\x00lodestartest")
	if err != nil {
		t.Fatal(err)
	}
	if allocated.Addr == leases[0].Addr || allocated.Addr == leases[1].Addr {
		t.Fatalf("allocator reused restored address %s", allocated.Addr)
	}
	if err := pool.Restore(nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("second restore error = %v, want ErrConflict", err)
	}
}

func TestPoolRestoreRejectsConflictsAtomically(t *testing.T) {
	pool, err := New(netip.MustParsePrefix("10.93.0.0/29"), netip.MustParseAddr("10.93.0.1"), 5)
	if err != nil {
		t.Fatal(err)
	}
	err = pool.Restore([]Lease{
		{Owner: "owner-a", Addr: netip.MustParseAddr("10.93.0.2")},
		{Owner: "owner-b", Addr: netip.MustParseAddr("10.93.0.2")},
	})
	if !errors.Is(err, ErrConflict) || pool.Used() != 0 {
		t.Fatalf("conflicting restore error=%v used=%d", err, pool.Used())
	}
}
