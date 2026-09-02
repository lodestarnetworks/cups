//go:build !linux

package udpstats

import (
	"net"
	"net/netip"
)

func enableOverflowReporting(*net.UDPConn) ([]byte, error) { return nil, nil }

func readDatagram(conn *net.UDPConn, payload, _ []byte) (n int, peer netip.AddrPort, cumulative uint32, present bool, err error) {
	n, peer, err = conn.ReadFromUDPAddrPort(payload)
	return n, peer, 0, false, err
}

func overflowCount([]byte) (uint32, bool) { return 0, false }
