package gtpv2

import "fmt"

// Message is a decoded GTPv2-C message with lossless unknown-IE retention.
type Message struct {
	Header Header
	IEs    []IE
}

func ParseMessage(packet []byte) (Message, error) {
	header, payload, err := Parse(packet)
	if err != nil {
		return Message{}, err
	}
	if header.Piggybacked || header.FrameLength != len(packet) {
		return Message{}, fmt.Errorf("%w: use ParseMessages for piggybacked or bundled data", ErrInvalidHeader)
	}
	if err := ValidateScope(header); err != nil {
		return Message{}, err
	}
	ies, err := ParseIEs(payload)
	if err != nil {
		return Message{}, err
	}
	return Message{Header: header, IEs: ies}, nil
}

// ParseMessages decodes one or more GTPv2-C messages in a UDP datagram and
// enforces the piggyback flag relationship between frames.
func ParseMessages(packet []byte) ([]Message, error) {
	messages := make([]Message, 0, 2)
	for len(packet) > 0 {
		header, payload, err := Parse(packet)
		if err != nil {
			return nil, err
		}
		if err := ValidateScope(header); err != nil {
			return nil, err
		}
		ies, err := ParseIEs(payload)
		if err != nil {
			return nil, err
		}
		messages = append(messages, Message{Header: header, IEs: ies})
		packet = packet[header.FrameLength:]
		if len(packet) > 0 && !header.Piggybacked {
			return nil, fmt.Errorf("%w: trailing frame without piggyback flag", ErrInvalidHeader)
		}
		if len(packet) == 0 && header.Piggybacked {
			return nil, fmt.Errorf("%w: piggyback flag without following frame", ErrInvalidHeader)
		}
		if len(messages) > 2 {
			return nil, fmt.Errorf("%w: more than two piggybacked messages", ErrInvalidHeader)
		}
	}
	return messages, nil
}

func (m Message) MarshalBinary() ([]byte, error) {
	payload, err := MarshalIEs(m.IEs)
	if err != nil {
		return nil, err
	}
	return Marshal(m.Header, payload)
}

func (m Message) Clone() Message {
	out := Message{Header: m.Header, IEs: make([]IE, len(m.IEs))}
	for index, ie := range m.IEs {
		out.IEs[index] = ie.Clone()
	}
	return out
}

func (m Message) Find(typ, instance uint8) (IE, bool) {
	return FindIE(m.IEs, typ, instance)
}

func (m *Message) Upsert(ie IE) {
	m.IEs = UpsertIE(m.IEs, ie)
}

func (m *Message) Remove(typ, instance uint8) {
	m.IEs = RemoveIE(m.IEs, typ, instance)
}
