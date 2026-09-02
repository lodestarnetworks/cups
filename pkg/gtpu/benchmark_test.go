package gtpu

import "testing"

func BenchmarkEncap(b *testing.B) {
	payload := make([]byte, 512)
	destination := make([]byte, len(payload)+8)
	header := Header{ProtocolType: true, MessageType: MessageGPDU, TEID: 0x10203040}
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, err := MarshalTo(destination, header, payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecap(b *testing.B) {
	payload := make([]byte, 512)
	wire, err := Marshal(Header{ProtocolType: true, MessageType: MessageGPDU, TEID: 0x10203040}, payload)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		header, inner, err := Parse(wire)
		if err != nil || header.TEID != 0x10203040 || len(inner) != len(payload) {
			b.Fatalf("parse header=%#v inner=%d err=%v", header, len(inner), err)
		}
	}
}
