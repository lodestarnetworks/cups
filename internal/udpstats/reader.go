// Package udpstats provides UDP receive helpers with kernel queue-overflow
// accounting where the operating system supports it.
package udpstats

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/ipv4"
)

// Reader wraps one UDP socket and reports the number of datagrams dropped by
// its kernel receive queue between successful reads.
type Reader struct {
	conn        *net.UDPConn
	batchConn   *ipv4.PacketConn
	control     []byte
	initialized bool
	lastDrops   uint32
}

// NewReader enables receive-queue overflow reporting on conn when supported.
func NewReader(conn *net.UDPConn) (*Reader, error) {
	if conn == nil {
		return nil, errors.New("udpstats: nil UDP connection")
	}
	control, err := enableOverflowReporting(conn)
	if err != nil {
		return nil, err
	}
	return &Reader{conn: conn, batchConn: ipv4.NewPacketConn(conn), control: control}, nil
}

// Datagram is one slot in a reusable UDP receive batch.
type Datagram struct {
	Buffer []byte
	N      int
	Peer   netip.AddrPort
}

// Batch owns fixed packet and control-message storage reused by every
// recvmmsg call. On operating systems without recvmmsg, ReadBatch safely
// returns one datagram at a time through the same API.
type Batch struct {
	Datagrams []Datagram
	messages  []ipv4.Message
}

// SendBatch owns reusable message, address, and IP storage for sendmmsg.
// Append does not allocate per packet and supports IPv4 and IPv6 peers.
type SendBatch struct {
	messages  []ipv4.Message
	addresses []net.UDPAddr
	ipStorage [][16]byte
	length    int
}

func NewSendBatch(size int) (*SendBatch, error) {
	if size <= 0 || size > 1024 {
		return nil, errors.New("udpstats: invalid send batch size")
	}
	batch := &SendBatch{
		messages: make([]ipv4.Message, size), addresses: make([]net.UDPAddr, size),
		ipStorage: make([][16]byte, size),
	}
	for index := range batch.messages {
		batch.messages[index].Buffers = make([][]byte, 1)
		batch.messages[index].Addr = &batch.addresses[index]
	}
	return batch, nil
}

func (b *SendBatch) Reset() {
	for index := 0; index < b.length; index++ {
		b.messages[index].Buffers[0] = nil
		b.messages[index].N = 0
	}
	b.length = 0
}

func (b *SendBatch) Append(payload []byte, peer netip.AddrPort) bool {
	if b == nil || b.length >= len(b.messages) || len(payload) == 0 || !peer.IsValid() {
		return false
	}
	index := b.length
	address := &b.addresses[index]
	address.Port = int(peer.Port())
	address.Zone = ""
	if peer.Addr().Is4() {
		value := peer.Addr().As4()
		copy(b.ipStorage[index][:4], value[:])
		address.IP = b.ipStorage[index][:4]
	} else {
		value := peer.Addr().As16()
		copy(b.ipStorage[index][:], value[:])
		address.IP = b.ipStorage[index][:]
	}
	b.messages[index].Buffers[0] = payload
	b.length++
	return true
}

func (b *SendBatch) Len() int {
	if b == nil {
		return 0
	}
	return b.length
}

// WriteBatch sends a complete prefix and retries normal partial sendmmsg
// completions. On error, sent is the exact prefix already accepted by the
// kernel; each UDP datagram remains atomic.
func (r *Reader) WriteBatch(batch *SendBatch) (sent int, err error) {
	if batch == nil || batch.length == 0 {
		return 0, nil
	}
	for sent < batch.length {
		n, writeErr := r.batchConn.WriteBatch(batch.messages[sent:batch.length], 0)
		sent += n
		if writeErr != nil {
			return sent, writeErr
		}
		if n == 0 {
			return sent, errors.New("udpstats: zero-length batch write")
		}
	}
	return sent, nil
}

func (r *Reader) NewBatch(size, maxDatagramBytes int) (*Batch, error) {
	if size <= 0 || size > 1024 || maxDatagramBytes <= 0 || maxDatagramBytes > 65_535 {
		return nil, errors.New("udpstats: invalid receive batch dimensions")
	}
	batch := &Batch{
		Datagrams: make([]Datagram, size),
		messages:  make([]ipv4.Message, size),
	}
	payloadStorage := make([]byte, size*maxDatagramBytes)
	controlStorage := make([]byte, size*len(r.control))
	for index := range batch.messages {
		payload := payloadStorage[index*maxDatagramBytes : (index+1)*maxDatagramBytes]
		batch.Datagrams[index].Buffer = payload
		batch.messages[index].Buffers = [][]byte{payload}
		if len(r.control) != 0 {
			batch.messages[index].OOB = controlStorage[index*len(r.control) : (index+1)*len(r.control)]
		}
	}
	return batch, nil
}

// ReadBatch receives up to the configured number of datagrams and returns all
// newly observed SO_RXQ_OVFL drops across the batch.
func (r *Reader) ReadBatch(batch *Batch) (n int, dropped uint64, err error) {
	if batch == nil || len(batch.messages) == 0 {
		return 0, 0, errors.New("udpstats: empty receive batch")
	}
	n, err = r.batchConn.ReadBatch(batch.messages, 0)
	if err != nil {
		return n, 0, err
	}
	for index := 0; index < n; index++ {
		message := &batch.messages[index]
		peer, ok := message.Addr.(*net.UDPAddr)
		if !ok {
			return index, dropped, fmt.Errorf("udpstats: unexpected UDP peer type %T", message.Addr)
		}
		batch.Datagrams[index].N = message.N
		batch.Datagrams[index].Peer = peer.AddrPort()
		if cumulative, present := overflowCount(message.OOB[:message.NN]); present {
			dropped += r.observe(cumulative)
		}
	}
	return n, dropped, nil
}

// ReadFromUDPAddrPort reads one datagram and returns any newly observed kernel
// receive-queue drops. The drop count handles the kernel's uint32 wraparound.
func (r *Reader) ReadFromUDPAddrPort(payload []byte) (n int, peer netip.AddrPort, dropped uint64, err error) {
	n, peer, cumulative, present, err := readDatagram(r.conn, payload, r.control)
	if err != nil || !present {
		return n, peer, 0, err
	}
	return n, peer, r.observe(cumulative), nil
}

// SetReadDeadline delegates to the wrapped UDP socket.
func (r *Reader) SetReadDeadline(deadline time.Time) error {
	return r.conn.SetReadDeadline(deadline)
}

func (r *Reader) observe(cumulative uint32) uint64 {
	if !r.initialized {
		r.initialized = true
		r.lastDrops = cumulative
		return uint64(cumulative)
	}
	var dropped uint64
	if cumulative >= r.lastDrops {
		dropped = uint64(cumulative - r.lastDrops)
	} else {
		dropped = uint64(^uint32(0)-r.lastDrops) + uint64(cumulative) + 1
	}
	r.lastDrops = cumulative
	return dropped
}
