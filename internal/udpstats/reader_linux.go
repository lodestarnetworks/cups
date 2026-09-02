//go:build linux

package udpstats

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/sys/unix"
)

func enableOverflowReporting(conn *net.UDPConn) ([]byte, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("udpstats: access UDP socket: %w", err)
	}
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		socketErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RXQ_OVFL, 1)
	}); err != nil {
		return nil, fmt.Errorf("udpstats: control UDP socket: %w", err)
	}
	if socketErr != nil {
		return nil, fmt.Errorf("udpstats: enable SO_RXQ_OVFL: %w", socketErr)
	}
	return make([]byte, unix.CmsgSpace(4)), nil
}

func readDatagram(conn *net.UDPConn, payload, control []byte) (n int, peer netip.AddrPort, cumulative uint32, present bool, err error) {
	n, controlBytes, _, peer, err := conn.ReadMsgUDPAddrPort(payload, control)
	if err != nil || controlBytes == 0 {
		return n, peer, 0, false, err
	}
	cumulative, present = overflowCount(control[:controlBytes])
	return n, peer, cumulative, present, nil
}

func overflowCount(control []byte) (uint32, bool) {
	messages, parseErr := unix.ParseSocketControlMessage(control)
	if parseErr != nil {
		return 0, false
	}
	for _, message := range messages {
		if message.Header.Level == unix.SOL_SOCKET && message.Header.Type == unix.SO_RXQ_OVFL && len(message.Data) >= 4 {
			return binary.NativeEndian.Uint32(message.Data[:4]), true
		}
	}
	return 0, false
}
