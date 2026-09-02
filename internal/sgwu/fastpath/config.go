// Package fastpath implements the optional SGW-U kernel packet path.
package fastpath

import (
	"net"
	"net/netip"
)

type Neighbour struct {
	IP  netip.Addr
	MAC net.HardwareAddr
}

type Side struct {
	Interface  string
	LocalIP    netip.Addr
	Neighbours []Neighbour
}

type Config struct {
	Access      Side
	Core        Side
	MaxSessions int
	MaxRules    int
}
