// Package gtpv2 implements defensive GTPv2-C wire primitives for LTE control-plane procedures.
package gtpv2

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const Version uint8 = 2

const (
	MessageEchoRequest                  uint8 = 1
	MessageEchoResponse                 uint8 = 2
	MessageVersionNotSupported          uint8 = 3
	MessageCreateSessionRequest         uint8 = 32
	MessageCreateSessionResponse        uint8 = 33
	MessageModifyBearerRequest          uint8 = 34
	MessageModifyBearerResponse         uint8 = 35
	MessageDeleteSessionRequest         uint8 = 36
	MessageDeleteSessionResponse        uint8 = 37
	MessageCreateBearerRequest          uint8 = 95
	MessageCreateBearerResponse         uint8 = 96
	MessageUpdateBearerRequest          uint8 = 97
	MessageUpdateBearerResponse         uint8 = 98
	MessageDeleteBearerRequest          uint8 = 99
	MessageDeleteBearerResponse         uint8 = 100
	MessageReleaseAccessBearersRequest  uint8 = 170
	MessageReleaseAccessBearersResponse uint8 = 171
	MessageDownlinkDataNotification     uint8 = 176
	MessageDownlinkDataNotificationAck  uint8 = 177
)

var (
	ErrTooShort           = errors.New("gtpv2: packet too short")
	ErrUnsupportedVersion = errors.New("gtpv2: unsupported version")
	ErrInvalidLength      = errors.New("gtpv2: invalid declared length")
	ErrInvalidHeader      = errors.New("gtpv2: invalid header")
)

type Header struct {
	Version         uint8
	Piggybacked     bool
	HasTEID         bool
	HasPriority     bool
	MessageType     uint8
	Length          uint16
	TEID            uint32
	SequenceNumber  uint32
	MessagePriority uint8
	FrameLength     int
}

func Parse(packet []byte) (Header, []byte, error) {
	if len(packet) < 8 {
		return Header{}, nil, ErrTooShort
	}
	h := Header{
		Version:     packet[0] >> 5,
		Piggybacked: packet[0]&0x10 != 0,
		HasTEID:     packet[0]&0x08 != 0,
		MessageType: packet[1],
		Length:      binary.BigEndian.Uint16(packet[2:4]),
	}
	if h.Version != Version {
		return h, nil, fmt.Errorf("%w: got %d, want %d", ErrUnsupportedVersion, h.Version, Version)
	}

	headerLength := 8
	if h.HasTEID {
		headerLength = 12
		h.HasPriority = packet[0]&0x04 != 0
	}
	if len(packet) < headerLength {
		return h, nil, ErrTooShort
	}
	h.FrameLength = 4 + int(h.Length)
	if h.FrameLength < headerLength || h.FrameLength > len(packet) {
		return h, nil, fmt.Errorf("%w: frame=%d header=%d available=%d", ErrInvalidLength, h.FrameLength, headerLength, len(packet))
	}

	if h.HasTEID {
		h.TEID = binary.BigEndian.Uint32(packet[4:8])
		h.SequenceNumber = uint32(packet[8])<<16 | uint32(packet[9])<<8 | uint32(packet[10])
		if h.HasPriority {
			h.MessagePriority = packet[11] >> 4
		}
	} else {
		h.SequenceNumber = uint32(packet[4])<<16 | uint32(packet[5])<<8 | uint32(packet[6])
	}
	if h.SequenceNumber > 0x00ff_ffff {
		return h, nil, ErrInvalidHeader
	}
	return h, packet[headerLength:h.FrameLength], nil
}

func Marshal(header Header, payload []byte) ([]byte, error) {
	if header.Version == 0 {
		header.Version = Version
	}
	if header.Version != Version {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrUnsupportedVersion, header.Version, Version)
	}
	if header.SequenceNumber > 0x00ff_ffff {
		return nil, fmt.Errorf("%w: sequence number exceeds 24 bits", ErrInvalidHeader)
	}
	if header.MessagePriority > 15 || (header.HasPriority && !header.HasTEID) {
		return nil, fmt.Errorf("%w: invalid message priority", ErrInvalidHeader)
	}

	headerLength := 8
	if header.HasTEID {
		headerLength = 12
	}
	total := headerLength + len(payload)
	if total-4 > 0xffff {
		return nil, fmt.Errorf("%w: payload too large", ErrInvalidLength)
	}
	packet := make([]byte, total)
	packet[0] = Version << 5
	if header.Piggybacked {
		packet[0] |= 0x10
	}
	if header.HasTEID {
		packet[0] |= 0x08
		if header.HasPriority {
			packet[0] |= 0x04
		}
	}
	packet[1] = header.MessageType
	binary.BigEndian.PutUint16(packet[2:4], uint16(total-4))
	if header.HasTEID {
		binary.BigEndian.PutUint32(packet[4:8], header.TEID)
		packet[8] = byte(header.SequenceNumber >> 16)
		packet[9] = byte(header.SequenceNumber >> 8)
		packet[10] = byte(header.SequenceNumber)
		if header.HasPriority {
			packet[11] = header.MessagePriority << 4
		}
	} else {
		packet[4] = byte(header.SequenceNumber >> 16)
		packet[5] = byte(header.SequenceNumber >> 8)
		packet[6] = byte(header.SequenceNumber)
	}
	copy(packet[headerLength:], payload)
	return packet, nil
}

func ValidateScope(header Header) error {
	switch header.MessageType {
	case MessageEchoRequest, MessageEchoResponse, MessageVersionNotSupported:
		if header.HasTEID {
			return fmt.Errorf("%w: message %d must not carry a TEID", ErrInvalidHeader, header.MessageType)
		}
	default:
		if !header.HasTEID {
			return fmt.Errorf("%w: message %d requires a TEID field", ErrInvalidHeader, header.MessageType)
		}
	}
	return nil
}
