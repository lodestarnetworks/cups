package pfcp

import "fmt"

type Message struct {
	Header Header
	IEs    []IE
}

func ParseMessage(packet []byte) (Message, error) {
	header, payload, err := Parse(packet)
	if err != nil {
		return Message{}, err
	}
	if header.FollowOn || header.FrameLength != len(packet) {
		return Message{}, fmt.Errorf("%w: use ParseMessages for bundled PFCP data", ErrInvalidHeader)
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
		if len(packet) > 0 && !header.FollowOn {
			return nil, fmt.Errorf("%w: trailing message without Follow On flag", ErrInvalidHeader)
		}
		if len(packet) == 0 && header.FollowOn {
			return nil, fmt.Errorf("%w: Follow On flag without another message", ErrInvalidHeader)
		}
		if len(messages) > 16 {
			return nil, fmt.Errorf("%w: too many bundled PFCP messages", ErrInvalidHeader)
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

func (m Message) Find(typ uint16) (IE, bool) {
	return FindIE(m.IEs, typ)
}
