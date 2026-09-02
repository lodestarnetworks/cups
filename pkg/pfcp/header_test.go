package pfcp

import (
	"errors"
	"testing"
)

func TestSessionHeaderRoundTrip(t *testing.T) {
	want := Header{HasSEID: true, HasPriority: true, MessageType: MessageSessionEstablishmentRequest, SEID: 0x1020304050607080, SequenceNumber: 0x010203, MessagePriority: 4}
	packet, err := Marshal(want, []byte{9, 8, 7})
	if err != nil {
		t.Fatal(err)
	}
	got, payload, err := Parse(packet)
	if err != nil {
		t.Fatal(err)
	}
	if got.SEID != want.SEID || got.SequenceNumber != want.SequenceNumber || got.MessagePriority != want.MessagePriority {
		t.Fatalf("header = %#v, want key fields from %#v", got, want)
	}
	if string(payload) != string([]byte{9, 8, 7}) {
		t.Fatalf("payload = %v", payload)
	}
}

func TestNodeHeaderRoundTrip(t *testing.T) {
	packet, err := Marshal(Header{MessageType: MessageHeartbeatRequest, SequenceNumber: 7}, nil)
	if err != nil {
		t.Fatal(err)
	}
	header, _, err := Parse(packet)
	if err != nil {
		t.Fatal(err)
	}
	if header.HasSEID || header.SequenceNumber != 7 {
		t.Fatalf("header = %#v", header)
	}
}

func TestParseRejectsTruncation(t *testing.T) {
	packet := []byte{0x21, MessageSessionModificationRequest, 0, 20, 0, 0, 0, 0}
	_, _, err := Parse(packet)
	if !errors.Is(err, ErrTooShort) && !errors.Is(err, ErrInvalidLength) {
		t.Fatalf("error = %v, want truncation error", err)
	}
}

func TestValidateScope(t *testing.T) {
	if err := ValidateScope(Header{MessageType: MessageHeartbeatRequest, HasSEID: true}); err == nil {
		t.Fatal("ValidateScope accepted SEID-bearing heartbeat")
	}
	if err := ValidateScope(Header{MessageType: MessageSessionDeletionRequest, HasSEID: true}); err != nil {
		t.Fatalf("ValidateScope rejected session message: %v", err)
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte{0x20, MessageHeartbeatRequest, 0, 4, 0, 0, 1, 0})
	f.Fuzz(func(t *testing.T, packet []byte) {
		_, _, _ = Parse(packet)
	})
}
