//go:build !linux

package dataplane

import (
	"errors"
	"os"
)

var osErrClosed = os.ErrClosed

func openPacketDevice(string) (packetDevice, error) {
	return nil, errors.New("pgwu dataplane: TUN is supported only on Linux")
}
