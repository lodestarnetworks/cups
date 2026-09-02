package gtpu

import (
	"errors"
	"testing"
)

func TestGPDURoundTrip(t *testing.T) {
	want := Header{ProtocolType: true, MessageType: MessageGPDU, TEID: 0x10203040}
	packet, err := Marshal(want, []byte{0x45, 0, 0, 20})
	if err != nil {
		t.Fatal(err)
	}
	got, payload, err := Parse(packet)
	if err != nil {
		t.Fatal(err)
	}
	if got.TEID != want.TEID || got.MessageType != MessageGPDU {
		t.Fatalf("header = %#v", got)
	}
	if string(payload) != string([]byte{0x45, 0, 0, 20}) {
		t.Fatalf("payload = %v", payload)
	}
}

func TestExtensionHeaderRoundTrip(t *testing.T) {
	want := Header{
		ProtocolType:   true,
		MessageType:    MessageGPDU,
		TEID:           42,
		Sequence:       true,
		SequenceNumber: 7,
		ExtensionHeaders: []ExtensionHeader{
			{Type: 0x85, Content: []byte{1, 2}},
			{Type: 0x40, Content: []byte{3, 4}},
		},
	}
	packet, err := Marshal(want, []byte{9})
	if err != nil {
		t.Fatal(err)
	}
	got, payload, err := Parse(packet)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.ExtensionHeaders) != 2 || got.ExtensionHeaders[1].Type != 0x40 {
		t.Fatalf("extensions = %#v", got.ExtensionHeaders)
	}
	if len(payload) != 1 || payload[0] != 9 {
		t.Fatalf("payload = %v", payload)
	}
}

func TestParseRejectsInvalidExtensionLength(t *testing.T) {
	packet := []byte{0x36, MessageGPDU, 0, 8, 0, 0, 0, 1, 0, 1, 0, 0x85, 0, 0, 0, 0}
	_, _, err := Parse(packet)
	if !errors.Is(err, ErrInvalidExtension) && !errors.Is(err, ErrTooShort) {
		t.Fatalf("error = %v, want invalid extension error", err)
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte{0x30, MessageGPDU, 0, 0, 0, 0, 0, 1})
	f.Fuzz(func(t *testing.T, packet []byte) {
		_, _, _ = Parse(packet)
	})
}
