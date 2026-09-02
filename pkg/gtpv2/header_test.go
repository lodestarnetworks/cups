package gtpv2

import (
	"errors"
	"testing"
)

func TestHeaderRoundTripWithTEIDAndPriority(t *testing.T) {
	want := Header{Version: Version, HasTEID: true, HasPriority: true, MessageType: MessageCreateSessionRequest, TEID: 0x10203040, SequenceNumber: 0x010203, MessagePriority: 7}
	packet, err := Marshal(want, []byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	got, payload, err := Parse(packet)
	if err != nil {
		t.Fatal(err)
	}
	if got.TEID != want.TEID || got.SequenceNumber != want.SequenceNumber || got.MessagePriority != want.MessagePriority {
		t.Fatalf("header = %#v, want key fields from %#v", got, want)
	}
	if string(payload) != string([]byte{1, 2, 3}) {
		t.Fatalf("payload = %v", payload)
	}
}

func TestEchoRoundTripWithoutTEID(t *testing.T) {
	packet, err := Marshal(Header{MessageType: MessageEchoRequest, SequenceNumber: 9}, nil)
	if err != nil {
		t.Fatal(err)
	}
	header, _, err := Parse(packet)
	if err != nil {
		t.Fatal(err)
	}
	if header.HasTEID || header.SequenceNumber != 9 {
		t.Fatalf("header = %#v", header)
	}
}

func TestParseRejectsTruncatedDeclaredLength(t *testing.T) {
	packet := []byte{0x48, MessageCreateSessionRequest, 0, 20, 0, 0, 0, 1, 0, 0, 1, 0}
	_, _, err := Parse(packet)
	if !errors.Is(err, ErrInvalidLength) {
		t.Fatalf("error = %v, want ErrInvalidLength", err)
	}
}

func TestValidateScope(t *testing.T) {
	if err := ValidateScope(Header{MessageType: MessageEchoRequest, HasTEID: true}); err == nil {
		t.Fatal("ValidateScope accepted TEID-bearing Echo Request")
	}
	if err := ValidateScope(Header{MessageType: MessageModifyBearerRequest, HasTEID: true}); err != nil {
		t.Fatalf("ValidateScope rejected valid session message: %v", err)
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte{0x40, MessageEchoRequest, 0, 4, 0, 0, 1, 0})
	f.Fuzz(func(t *testing.T, packet []byte) {
		_, _, _ = Parse(packet)
	})
}
