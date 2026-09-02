package rules

import (
	"fmt"
	"net/netip"
	"testing"
)

var lookupBenchmarkSizes = [...]int{1, 1_000, 100_000, 1_000_000}

func BenchmarkLookup(b *testing.B) {
	for _, size := range lookupBenchmarkSizes {
		b.Run(fmt.Sprintf("sessions=%d", size), func(b *testing.B) {
			store, teid := benchmarkStore(b, size)
			b.ReportAllocs()
			b.ResetTimer()
			for index := 0; index < b.N; index++ {
				if _, ok := store.LookupUplink(teid); !ok {
					b.Fatal("lookup failed")
				}
			}
		})
	}
}

func BenchmarkLookupParallel(b *testing.B) {
	for _, size := range lookupBenchmarkSizes {
		b.Run(fmt.Sprintf("sessions=%d", size), func(b *testing.B) {
			store, teid := benchmarkStore(b, size)
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if _, ok := store.LookupUplink(teid); !ok {
						b.Fatal("lookup failed")
					}
				}
			})
		})
	}
}

func benchmarkStore(b *testing.B, size int) (*Store, uint32) {
	b.Helper()
	store := NewStoreWithLimit(size)
	local := netip.MustParseAddr("10.200.0.20")
	remote := netip.MustParseAddr("10.200.0.10")
	for index := 0; index < size; index++ {
		value := uint32(index + 1)
		ue := netip.AddrFrom4([4]byte{10, byte(value >> 16), byte(value >> 8), byte(value)})
		if _, err := store.Create(Session{
			CPSEID: uint64(value), UPSEID: uint64(value), UEIPv4: ue,
			Local: Tunnel{TEID: value, IP: local}, Remote: Tunnel{TEID: value + uint32(size), IP: remote},
			UplinkGateOpen: true, DownlinkGateOpen: true,
		}); err != nil {
			b.Fatalf("create session %d: %v", index, err)
		}
	}
	return store, uint32(size/2 + 1)
}
