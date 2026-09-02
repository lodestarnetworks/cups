// Package pfcp implements defensive PFCP wire primitives for the LTE Sxa interface.
package pfcp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const Version uint8 = 1

const (
	MessageHeartbeatRequest             uint8 = 1
	MessageHeartbeatResponse            uint8 = 2
	MessageAssociationSetupRequest      uint8 = 5
	MessageAssociationSetupResponse     uint8 = 6
	MessageAssociationUpdateRequest     uint8 = 7
	MessageAssociationUpdateResponse    uint8 = 8
	MessageAssociationReleaseRequest    uint8 = 9
	MessageAssociationReleaseResponse   uint8 = 10
	MessageVersionNotSupportedResponse  uint8 = 11
	MessageNodeReportRequest            uint8 = 12
	MessageNodeReportResponse           uint8 = 13
	MessageSessionSetDeletionRequest    uint8 = 14
	MessageSessionSetDeletionResponse   uint8 = 15
	MessageSessionEstablishmentRequest  uint8 = 50
	MessageSessionEstablishmentResponse uint8 = 51
	MessageSessionModificationRequest   uint8 = 52
	MessageSessionModificationResponse  uint8 = 53
	MessageSessionDeletionRequest       uint8 = 54
	MessageSessionDeletionResponse      uint8 = 55
	MessageSessionReportRequest         uint8 = 56
	MessageSessionReportResponse        uint8 = 57
)

var (
	ErrTooShort           = errors.New("pfcp: packet too short")
	ErrUnsupportedVersion = errors.New("pfcp: unsupported version")
	ErrInvalidLength      = errors.New("pfcp: invalid declared length")
	ErrInvalidHeader      = errors.New("pfcp: invalid header")
)

type Header struct {
	Version         uint8
	FollowOn        bool
	HasSEID         bool
	HasPriority     bool
	MessageType     uint8
	Length          uint16
	SEID            uint64
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
		FollowOn:    packet[0]&0x04 != 0,
		HasPriority: packet[0]&0x02 != 0,
		HasSEID:     packet[0]&0x01 != 0,
		MessageType: packet[1],
		Length:      binary.BigEndian.Uint16(packet[2:4]),
	}
	if h.Version != Version {
		return h, nil, fmt.Errorf("%w: got %d, want %d", ErrUnsupportedVersion, h.Version, Version)
	}
	headerLength := 8
	if h.HasSEID {
		headerLength = 16
	}
	if len(packet) < headerLength {
		return h, nil, ErrTooShort
	}
	h.FrameLength = 4 + int(h.Length)
	if h.FrameLength < headerLength || h.FrameLength > len(packet) {
		return h, nil, fmt.Errorf("%w: frame=%d header=%d available=%d", ErrInvalidLength, h.FrameLength, headerLength, len(packet))
	}
	if h.HasSEID {
		h.SEID = binary.BigEndian.Uint64(packet[4:12])
		h.SequenceNumber = uint32(packet[12])<<16 | uint32(packet[13])<<8 | uint32(packet[14])
		if h.HasPriority {
			h.MessagePriority = packet[15] >> 4
		}
	} else {
		h.SequenceNumber = uint32(packet[4])<<16 | uint32(packet[5])<<8 | uint32(packet[6])
		if h.HasPriority {
			h.MessagePriority = packet[7] >> 4
		}
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
	if header.SequenceNumber > 0x00ff_ffff || header.MessagePriority > 15 {
		return nil, ErrInvalidHeader
	}
	headerLength := 8
	if header.HasSEID {
		headerLength = 16
	}
	total := headerLength + len(payload)
	if total-4 > 0xffff {
		return nil, fmt.Errorf("%w: payload too large", ErrInvalidLength)
	}
	packet := make([]byte, total)
	packet[0] = Version << 5
	if header.FollowOn {
		packet[0] |= 0x04
	}
	if header.HasPriority {
		packet[0] |= 0x02
	}
	if header.HasSEID {
		packet[0] |= 0x01
	}
	packet[1] = header.MessageType
	binary.BigEndian.PutUint16(packet[2:4], uint16(total-4))
	if header.HasSEID {
		binary.BigEndian.PutUint64(packet[4:12], header.SEID)
		packet[12] = byte(header.SequenceNumber >> 16)
		packet[13] = byte(header.SequenceNumber >> 8)
		packet[14] = byte(header.SequenceNumber)
		if header.HasPriority {
			packet[15] = header.MessagePriority << 4
		}
	} else {
		packet[4] = byte(header.SequenceNumber >> 16)
		packet[5] = byte(header.SequenceNumber >> 8)
		packet[6] = byte(header.SequenceNumber)
		if header.HasPriority {
			packet[7] = header.MessagePriority << 4
		}
	}
	copy(packet[headerLength:], payload)
	return packet, nil
}

func ValidateScope(header Header) error {
	sessionMessage := header.MessageType >= MessageSessionEstablishmentRequest && header.MessageType <= MessageSessionReportResponse
	if sessionMessage != header.HasSEID {
		return fmt.Errorf("%w: message %d has invalid S flag", ErrInvalidHeader, header.MessageType)
	}
	return nil
}
