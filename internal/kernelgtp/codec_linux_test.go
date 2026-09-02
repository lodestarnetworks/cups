//go:build linux

package kernelgtp

import (
	"net/netip"
	"testing"
)

func TestContextCodecRoundTrip(t *testing.T) {
	want := Context{
		LinkIndex: 42, UEIPv4: netip.MustParseAddr("10.200.1.9"), PeerIPv4: netip.MustParseAddr("10.90.3.8"),
		IncomingTEID: 0x10203040, OutgoingTEID: 0x50607080,
	}
	data, err := encodeContext(want, true)
	if err != nil {
		t.Fatal(err)
	}
	got, supported, err := decodeContext(data)
	if err != nil {
		t.Fatal(err)
	}
	if !supported {
		t.Fatal("GTPv1 context reported unsupported")
	}
	if got != want {
		t.Fatalf("round trip mismatch: got %+v want %+v", got, want)
	}
}

func TestDecodeContextRejectsTruncatedAttribute(t *testing.T) {
	if _, _, err := decodeContext([]byte{8, 0, 1, 0, 1}); err == nil {
		t.Fatal("expected malformed netlink attribute error")
	}
}
