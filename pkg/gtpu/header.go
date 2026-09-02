// Package gtpu implements defensive GTP-U wire primitives for LTE user-plane traffic.
package gtpu

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const Version uint8 = 1

const (
	MessageEchoRequest     uint8 = 1
	MessageEchoResponse    uint8 = 2
	MessageErrorIndication uint8 = 26
	MessageEndMarker       uint8 = 254
	MessageGPDU            uint8 = 255
)

var (
	ErrTooShort           = errors.New("gtpu: packet too short")
	ErrUnsupportedVersion = errors.New("gtpu: unsupported version")
	ErrInvalidLength      = errors.New("gtpu: invalid declared length")
	ErrInvalidHeader      = errors.New("gtpu: invalid header")
	ErrInvalidExtension   = errors.New("gtpu: invalid extension header")
	ErrBufferTooSmall     = errors.New("gtpu: destination buffer too small")
)

type ExtensionHeader struct {
	Type    uint8
	Content []byte
}

type Header struct {
	Version          uint8
	ProtocolType     bool
	Extension        bool
	Sequence         bool
	NPDU             bool
	MessageType      uint8
	Length           uint16
	TEID             uint32
	SequenceNumber   uint16
	NPDUNumber       uint8
	ExtensionHeaders []ExtensionHeader
	FrameLength      int
}

func Parse(packet []byte) (Header, []byte, error) {
	if len(packet) < 8 {
		return Header{}, nil, ErrTooShort
	}
	h := Header{
		Version:      packet[0] >> 5,
		ProtocolType: packet[0]&0x10 != 0,
		Extension:    packet[0]&0x04 != 0,
		Sequence:     packet[0]&0x02 != 0,
		NPDU:         packet[0]&0x01 != 0,
		MessageType:  packet[1],
		Length:       binary.BigEndian.Uint16(packet[2:4]),
		TEID:         binary.BigEndian.Uint32(packet[4:8]),
	}
	if h.Version != Version {
		return h, nil, fmt.Errorf("%w: got %d, want %d", ErrUnsupportedVersion, h.Version, Version)
	}
	if !h.ProtocolType {
		return h, nil, fmt.Errorf("%w: protocol type bit is not set", ErrInvalidHeader)
	}
	h.FrameLength = 8 + int(h.Length)
	if h.FrameLength < 8 || h.FrameLength > len(packet) {
		return h, nil, fmt.Errorf("%w: frame=%d available=%d", ErrInvalidLength, h.FrameLength, len(packet))
	}

	offset := 8
	var nextExtension uint8
	if h.Extension || h.Sequence || h.NPDU {
		if h.FrameLength < 12 {
			return h, nil, ErrTooShort
		}
		h.SequenceNumber = binary.BigEndian.Uint16(packet[8:10])
		h.NPDUNumber = packet[10]
		nextExtension = packet[11]
		offset = 12
	}
	if h.Extension && nextExtension == 0 {
		return h, nil, fmt.Errorf("%w: E flag set without extension type", ErrInvalidExtension)
	}
	if !h.Extension && nextExtension != 0 {
		return h, nil, fmt.Errorf("%w: extension type present without E flag", ErrInvalidExtension)
	}

	for nextExtension != 0 {
		if offset >= h.FrameLength {
			return h, nil, ErrTooShort
		}
		units := int(packet[offset])
		if units == 0 {
			return h, nil, fmt.Errorf("%w: zero length", ErrInvalidExtension)
		}
		extensionLength := units * 4
		if offset+extensionLength > h.FrameLength || extensionLength < 2 {
			return h, nil, fmt.Errorf("%w: length=%d", ErrInvalidExtension, extensionLength)
		}
		content := append([]byte(nil), packet[offset+1:offset+extensionLength-1]...)
		h.ExtensionHeaders = append(h.ExtensionHeaders, ExtensionHeader{Type: nextExtension, Content: content})
		nextExtension = packet[offset+extensionLength-1]
		offset += extensionLength
	}
	return h, packet[offset:h.FrameLength], nil
}

func Marshal(header Header, payload []byte) ([]byte, error) {
	header, total, err := marshalPlan(header, len(payload))
	if err != nil {
		return nil, err
	}
	packet := make([]byte, total)
	if _, err := marshalPlanned(packet, header, payload); err != nil {
		return nil, err
	}
	return packet, nil
}

// MarshalTo writes one GTP-U frame into caller-owned storage. It is the
// zero-allocation encoder used by the steady-state forwarding path.
func MarshalTo(destination []byte, header Header, payload []byte) (int, error) {
	header, total, err := marshalPlan(header, len(payload))
	if err != nil {
		return 0, err
	}
	if len(destination) < total {
		return 0, fmt.Errorf("%w: need=%d have=%d", ErrBufferTooSmall, total, len(destination))
	}
	return marshalPlanned(destination[:total], header, payload)
}

func marshalPlan(header Header, payloadLength int) (Header, int, error) {
	if header.Version == 0 {
		header.Version = Version
	}
	if header.Version != Version {
		return Header{}, 0, fmt.Errorf("%w: got %d, want %d", ErrUnsupportedVersion, header.Version, Version)
	}
	if !header.ProtocolType {
		header.ProtocolType = true
	}
	if len(header.ExtensionHeaders) > 0 {
		header.Extension = true
	}
	optional := header.Extension || header.Sequence || header.NPDU
	extensionLength := 0
	for _, extension := range header.ExtensionHeaders {
		if extension.Type == 0 || (len(extension.Content)+2)%4 != 0 || (len(extension.Content)+2)/4 > 255 {
			return Header{}, 0, fmt.Errorf("%w: type=%d content-length=%d", ErrInvalidExtension, extension.Type, len(extension.Content))
		}
		extensionLength += len(extension.Content) + 2
	}
	headerLength := 8
	if optional {
		headerLength = 12
	}
	total := headerLength + extensionLength + payloadLength
	if total-8 > 0xffff {
		return Header{}, 0, fmt.Errorf("%w: payload too large", ErrInvalidLength)
	}
	return header, total, nil
}

func marshalPlanned(packet []byte, header Header, payload []byte) (int, error) {
	total := len(packet)
	optional := header.Extension || header.Sequence || header.NPDU
	packet[0] = Version<<5 | 0x10
	if header.Extension {
		packet[0] |= 0x04
	}
	if header.Sequence {
		packet[0] |= 0x02
	}
	if header.NPDU {
		packet[0] |= 0x01
	}
	packet[1] = header.MessageType
	binary.BigEndian.PutUint16(packet[2:4], uint16(total-8))
	binary.BigEndian.PutUint32(packet[4:8], header.TEID)
	offset := 8
	if optional {
		binary.BigEndian.PutUint16(packet[8:10], header.SequenceNumber)
		packet[10] = header.NPDUNumber
		if len(header.ExtensionHeaders) > 0 {
			packet[11] = header.ExtensionHeaders[0].Type
		}
		offset = 12
	}
	for index, extension := range header.ExtensionHeaders {
		length := len(extension.Content) + 2
		packet[offset] = byte(length / 4)
		copy(packet[offset+1:], extension.Content)
		if index+1 < len(header.ExtensionHeaders) {
			packet[offset+length-1] = header.ExtensionHeaders[index+1].Type
		}
		offset += length
	}
	copy(packet[offset:], payload)
	return total, nil
}
