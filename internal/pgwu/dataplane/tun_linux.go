//go:build linux

package dataplane

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	tunSetIFF = 0x400454ca
	iffTUN    = 0x0001
	iffNoPI   = 0x1000
)

var osErrClosed = os.ErrClosed

type tunDevice struct {
	file *os.File
	name string
}

func openPacketDevice(name string) (packetDevice, error) {
	if name == "" {
		name = "lspgwu0"
	}
	if len(name) > 15 {
		return nil, errors.New("pgwu dataplane: tunnel name exceeds 15 bytes")
	}
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	var request [40]byte
	copy(request[:16], name)
	binary.NativeEndian.PutUint16(request[16:18], iffTUN|iffNoPI)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), tunSetIFF, uintptr(unsafe.Pointer(&request[0])))
	if errno != 0 {
		_ = file.Close()
		return nil, fmt.Errorf("create TUN %s: %w", name, errno)
	}
	actualEnd := 0
	for actualEnd < 16 && request[actualEnd] != 0 {
		actualEnd++
	}
	return &tunDevice{file: file, name: string(request[:actualEnd])}, nil
}

func (t *tunDevice) Read(packet []byte) (int, error)  { return t.file.Read(packet) }
func (t *tunDevice) Write(packet []byte) (int, error) { return t.file.Write(packet) }
func (t *tunDevice) Close() error                     { return t.file.Close() }
func (t *tunDevice) Name() string                     { return t.name }
