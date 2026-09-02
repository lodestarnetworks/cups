package rules

import (
	"fmt"
	"testing"
)

var sgwLookupBenchmarkSizes = [...]int{1, 1_000, 100_000, 1_000_000}

func BenchmarkLookupSGWU(b *testing.B) {
	for _, size := range sgwLookupBenchmarkSizes {
		b.Run(fmt.Sprintf("sessions=%d", size), func(b *testing.B) {
			store, teid := benchmarkPacketIndex(size)
			b.ReportAllocs()
			b.ResetTimer()
			for index := 0; index < b.N; index++ {
				if _, ok := store.LookupPacket(SourceAccess, teid); !ok {
					b.Fatal("lookup failed")
				}
			}
		})
	}
}

func BenchmarkLookupParallelSGWU(b *testing.B) {
	for _, size := range sgwLookupBenchmarkSizes {
		b.Run(fmt.Sprintf("sessions=%d", size), func(b *testing.B) {
			store, teid := benchmarkPacketIndex(size)
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if _, ok := store.LookupPacket(SourceAccess, teid); !ok {
						b.Fatal("lookup failed")
					}
				}
			})
		})
	}
}

func benchmarkPacketIndex(size int) (*Store, uint32) {
	store := NewStoreWithLimit(size)
	generation := &ruleGeneration{}
	generation.active.Store(true)
	for index := 0; index < size; index++ {
		teid := uint32(index + 1)
		store.byTunnel.Store(tunnelKey{Source: SourceAccess, TEID: teid}, PacketRule{UPSEID: uint64(teid), Revision: 1, generation: generation})
	}
	return store, uint32(size/2 + 1)
}
