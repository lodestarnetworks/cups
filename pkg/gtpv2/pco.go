package gtpv2

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// Protocol and container identifiers from the Protocol Configuration Options
// element used by LTE IPv4 PDNs.
const (
	PCOProtocolPPP uint8 = 0

	PCOContainerIPCP          uint16 = 0x8021
	PCOContainerPCSCFIPv6     uint16 = 0x0001
	PCOContainerDNSServerIPv6 uint16 = 0x0003
	PCOContainerPCSCFIPv4     uint16 = 0x000c
	PCOContainerDNSServerIPv4 uint16 = 0x000d
	PCOContainerIPv4LinkMTU   uint16 = 0x0010
	PCOContainerLocalAddrTFT  uint16 = 0x0011
	PCOContainerPCSCFReselect uint16 = 0x0012

	IPCPConfigureRequest uint8 = 1
	IPCPConfigureAck     uint8 = 2
	IPCPOptionIPv4       uint8 = 3
	IPCPOptionPrimaryDNS uint8 = 129
	IPCPOptionSecondDNS  uint8 = 131

	MaxPCOLength     = 251
	maxPCOContainers = 32
	maxIPCPRequests  = 4
)

// PCOContainer is one PPP protocol or 3GPP container carried by PCO. Contents
// is always owned by the struct and never aliases a parsed packet.
type PCOContainer struct {
	ID       uint16
	Contents []byte
}

// PCO is the bounded, defensive representation of TS 24.008 Protocol
// Configuration Options.
type PCO struct {
	Extension             bool
	ConfigurationProtocol uint8
	Containers            []PCOContainer
}

// PCOResponseProfile contains APN policy values that are returned only when
// the UE asks for the corresponding PCO container.
type PCOResponseProfile struct {
	DNSIPv4     []netip.Addr
	PCSCFIPv4   []netip.Addr
	IPv4LinkMTU uint16
}

func NewPCOIE(instance uint8, pco PCO) (IE, error) {
	if instance > 15 || pco.ConfigurationProtocol > 7 {
		return IE{}, fmt.Errorf("%w: invalid PCO instance or configuration protocol", ErrMalformedIE)
	}
	if len(pco.Containers) > maxPCOContainers {
		return IE{}, fmt.Errorf("%w: PCO has too many containers", ErrMalformedIE)
	}
	total := 1
	for _, container := range pco.Containers {
		if len(container.Contents) > 255 {
			return IE{}, fmt.Errorf("%w: PCO container 0x%04x is too large", ErrMalformedIE, container.ID)
		}
		total += 3 + len(container.Contents)
		if total > MaxPCOLength {
			return IE{}, fmt.Errorf("%w: PCO exceeds %d octets", ErrMalformedIE, MaxPCOLength)
		}
	}
	value := make([]byte, total)
	value[0] = pco.ConfigurationProtocol & 0x07
	if pco.Extension {
		value[0] |= 0x80
	}
	offset := 1
	for _, container := range pco.Containers {
		binary.BigEndian.PutUint16(value[offset:offset+2], container.ID)
		value[offset+2] = byte(len(container.Contents))
		copy(value[offset+3:], container.Contents)
		offset += 3 + len(container.Contents)
	}
	return IE{Type: IEPCO, Instance: instance, Value: value}, nil
}

func (ie IE) PCO() (PCO, error) {
	if ie.Type != IEPCO || len(ie.Value) < 1 || len(ie.Value) > MaxPCOLength {
		return PCO{}, fmt.Errorf("%w: invalid PCO IE length", ErrMalformedIE)
	}
	if ie.Value[0]&0x78 != 0 {
		return PCO{}, fmt.Errorf("%w: non-zero PCO spare bits", ErrMalformedIE)
	}
	out := PCO{
		Extension:             ie.Value[0]&0x80 != 0,
		ConfigurationProtocol: ie.Value[0] & 0x07,
		Containers:            make([]PCOContainer, 0, min((len(ie.Value)-1)/3, 8)),
	}
	for offset := 1; offset < len(ie.Value); {
		if len(out.Containers) >= maxPCOContainers || len(ie.Value)-offset < 3 {
			return PCO{}, fmt.Errorf("%w: truncated or excessive PCO containers", ErrMalformedIE)
		}
		id := binary.BigEndian.Uint16(ie.Value[offset : offset+2])
		length := int(ie.Value[offset+2])
		offset += 3
		if length > len(ie.Value)-offset {
			return PCO{}, fmt.Errorf("%w: truncated PCO container 0x%04x", ErrMalformedIE, id)
		}
		contents := append([]byte(nil), ie.Value[offset:offset+length]...)
		out.Containers = append(out.Containers, PCOContainer{ID: id, Contents: contents})
		offset += length
	}
	return out, nil
}

// BuildPCOResponse implements the IPv4 DNS and link-MTU negotiation used by
// LTE handsets. It supports both direct 3GPP DNS containers and DNS options
// nested in an IPCP Configure-Request.
func BuildPCOResponse(request PCO, profile PCOResponseProfile) (PCO, error) {
	dns, err := normalizePCODNS(profile.DNSIPv4)
	if err != nil {
		return PCO{}, err
	}
	pcscf, err := normalizePCOIPv4(profile.PCSCFIPv4, "P-CSCF")
	if err != nil {
		return PCO{}, err
	}
	response := PCO{
		Extension:             request.Extension,
		ConfigurationProtocol: request.ConfigurationProtocol,
		Containers:            make([]PCOContainer, 0, len(request.Containers)),
	}
	directDNSAnswered := false
	pcscfAnswered := false
	mtuAnswered := false
	ipcpRequests := 0
	for _, container := range request.Containers {
		switch container.ID {
		case PCOContainerIPCP:
			if ipcpRequests >= maxIPCPRequests {
				continue
			}
			contents, answer, err := buildIPCPResponse(container.Contents, dns)
			if err != nil {
				return PCO{}, err
			}
			if answer {
				response.Containers = append(response.Containers, PCOContainer{ID: container.ID, Contents: contents})
				ipcpRequests++
			}
		case PCOContainerDNSServerIPv4:
			if directDNSAnswered {
				continue
			}
			for _, address := range dns {
				raw := address.As4()
				response.Containers = append(response.Containers, PCOContainer{ID: container.ID, Contents: append([]byte(nil), raw[:]...)})
			}
			directDNSAnswered = true
		case PCOContainerPCSCFIPv4:
			if pcscfAnswered {
				continue
			}
			for _, address := range pcscf {
				raw := address.As4()
				response.Containers = append(response.Containers, PCOContainer{ID: container.ID, Contents: append([]byte(nil), raw[:]...)})
			}
			pcscfAnswered = true
		case PCOContainerIPv4LinkMTU:
			if mtuAnswered || profile.IPv4LinkMTU == 0 {
				continue
			}
			contents := make([]byte, 2)
			binary.BigEndian.PutUint16(contents, profile.IPv4LinkMTU)
			response.Containers = append(response.Containers, PCOContainer{ID: container.ID, Contents: contents})
			mtuAnswered = true
		}
	}
	if _, err := NewPCOIE(0, response); err != nil {
		return PCO{}, err
	}
	return response, nil
}

func normalizePCODNS(addresses []netip.Addr) ([]netip.Addr, error) {
	return normalizePCOIPv4(addresses, "DNS server")
}

func normalizePCOIPv4(addresses []netip.Addr, purpose string) ([]netip.Addr, error) {
	if len(addresses) > 2 {
		return nil, fmt.Errorf("%w: PCO supports at most two IPv4 %s addresses", ErrMalformedIE, purpose)
	}
	out := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		if !address.Is4() || address.IsUnspecified() || address.IsMulticast() {
			return nil, fmt.Errorf("%w: invalid PCO IPv4 %s", ErrMalformedIE, purpose)
		}
		out = append(out, address.Unmap())
	}
	return out, nil
}

func buildIPCPResponse(request []byte, dns []netip.Addr) ([]byte, bool, error) {
	if len(request) < 4 {
		return nil, false, fmt.Errorf("%w: truncated IPCP packet", ErrMalformedIE)
	}
	packetLength := int(binary.BigEndian.Uint16(request[2:4]))
	if packetLength != len(request) || packetLength < 4 {
		return nil, false, fmt.Errorf("%w: invalid IPCP packet length", ErrMalformedIE)
	}
	if request[0] != IPCPConfigureRequest {
		return nil, false, nil
	}
	response := []byte{IPCPConfigureAck, request[1], 0, 4}
	for offset := 4; offset < len(request); {
		if len(request)-offset < 2 {
			return nil, false, fmt.Errorf("%w: truncated IPCP option", ErrMalformedIE)
		}
		optionType := request[offset]
		optionLength := int(request[offset+1])
		if optionLength < 2 || optionLength > len(request)-offset {
			return nil, false, fmt.Errorf("%w: invalid IPCP option length", ErrMalformedIE)
		}
		switch optionType {
		case IPCPOptionPrimaryDNS:
			if optionLength < 6 {
				return nil, false, fmt.Errorf("%w: short primary DNS IPCP option", ErrMalformedIE)
			}
			if len(dns) > 0 {
				response = appendIPCPDNS(response, optionType, dns[0])
			}
		case IPCPOptionSecondDNS:
			if optionLength < 6 {
				return nil, false, fmt.Errorf("%w: short secondary DNS IPCP option", ErrMalformedIE)
			}
			if len(dns) > 1 {
				response = appendIPCPDNS(response, optionType, dns[1])
			}
		}
		offset += optionLength
	}
	binary.BigEndian.PutUint16(response[2:4], uint16(len(response)))
	return response, true, nil
}

func appendIPCPDNS(target []byte, optionType uint8, address netip.Addr) []byte {
	raw := address.As4()
	target = append(target, optionType, 6)
	return append(target, raw[:]...)
}
