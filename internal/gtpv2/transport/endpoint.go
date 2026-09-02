// Package transport provides bounded GTPv2-C/UDP delivery and transaction handling.
package transport

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lodestarnetworks/cups/internal/responsecache"
	"github.com/lodestarnetworks/cups/internal/udpstats"
	"github.com/lodestarnetworks/cups/pkg/gtpv2"
)

var (
	ErrClosed               = errors.New("gtpv2 transport: endpoint closed")
	ErrTimeout              = errors.New("gtpv2 transport: transaction timed out")
	ErrUnsupportedRequest   = errors.New("gtpv2 transport: unsupported request type")
	ErrTransactionCollision = errors.New("gtpv2 transport: transaction collision")
)

const maxInflightResponseReplays = 8

type Config struct {
	RetransmitTimeout time.Duration
	MaxRetransmits    int
	MaxWorkers        int
	ResponseCacheSize int
	ResponseCacheTTL  time.Duration
	SocketBufferBytes int
}

func DefaultConfig() Config {
	return Config{
		RetransmitTimeout: time.Second,
		MaxRetransmits:    3,
		MaxWorkers:        128,
		ResponseCacheSize: 2048,
		ResponseCacheTTL:  30 * time.Second,
		SocketBufferBytes: 4 << 20,
	}
}

type Handler func(context.Context, netip.AddrPort, gtpv2.Message) (*gtpv2.Message, error)

type Counters struct {
	Received              uint64
	Sent                  uint64
	Malformed             uint64
	Retransmitted         uint64
	TimedOut              uint64
	CacheHits             uint64
	WorkerDrops           uint64
	SocketDrops           uint64
	ActiveTransactions    uint64
	TransactionCollisions uint64
	InflightDuplicates    uint64
	InflightReplays       uint64
}

type transactionKey struct {
	peer     netip.AddrPort
	sequence uint32
}

type requestKey struct {
	transactionKey
	typ uint8
}

type pendingTransaction struct {
	expectedType uint8
	response     chan gtpv2.Message
}

type inflightRequest struct {
	replays int
}

type Endpoint struct {
	conn    *net.UDPConn
	reader  *udpstats.Reader
	handler Handler
	config  Config
	workers chan struct{}
	next    atomic.Uint32

	pendingMu  sync.Mutex
	pending    map[transactionKey]pendingTransaction
	cache      *responsecache.Cache[requestKey]
	inflightMu sync.Mutex
	inflight   map[requestKey]*inflightRequest

	received              atomic.Uint64
	sent                  atomic.Uint64
	malformed             atomic.Uint64
	retransmitted         atomic.Uint64
	timedOut              atomic.Uint64
	cacheHits             atomic.Uint64
	workerDrops           atomic.Uint64
	socketDrops           atomic.Uint64
	transactionCollisions atomic.Uint64
	inflightDuplicates    atomic.Uint64
	inflightReplays       atomic.Uint64
	closed                chan struct{}
	closeOnce             sync.Once
}

func Listen(local netip.AddrPort, handler Handler, config Config) (*Endpoint, error) {
	if !local.Addr().IsValid() {
		return nil, errors.New("gtpv2 transport: local address is required")
	}
	if config.RetransmitTimeout <= 0 || config.MaxRetransmits < 0 || config.MaxWorkers <= 0 || config.ResponseCacheSize < 0 || config.ResponseCacheTTL < 0 || config.SocketBufferBytes < 0 {
		return nil, errors.New("gtpv2 transport: invalid configuration")
	}
	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(local))
	if err != nil {
		return nil, fmt.Errorf("listen GTPv2-C on %s: %w", local, err)
	}
	if config.SocketBufferBytes > 0 {
		if err := conn.SetReadBuffer(config.SocketBufferBytes); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("size GTPv2-C receive buffer: %w", err)
		}
		if err := conn.SetWriteBuffer(config.SocketBufferBytes); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("size GTPv2-C send buffer: %w", err)
		}
	}
	reader, err := udpstats.NewReader(conn)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("enable GTPv2-C receive-queue accounting: %w", err)
	}
	var seed [4]byte
	if _, err := rand.Read(seed[:]); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("seed GTPv2-C sequence number: %w", err)
	}
	endpoint := &Endpoint{
		conn: conn, reader: reader, handler: handler, config: config,
		workers: make(chan struct{}, config.MaxWorkers),
		pending: make(map[transactionKey]pendingTransaction),
		cache:   responsecache.New[requestKey](config.ResponseCacheSize, config.ResponseCacheTTL), closed: make(chan struct{}),
		inflight: make(map[requestKey]*inflightRequest),
	}
	endpoint.next.Store(binary.BigEndian.Uint32(seed[:]) & 0x00ff_ffff)
	return endpoint, nil
}

func (e *Endpoint) LocalAddr() netip.AddrPort {
	return e.conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

func (e *Endpoint) Counters() Counters {
	e.pendingMu.Lock()
	active := len(e.pending)
	e.pendingMu.Unlock()
	return Counters{
		Received: e.received.Load(), Sent: e.sent.Load(), Malformed: e.malformed.Load(),
		Retransmitted: e.retransmitted.Load(), TimedOut: e.timedOut.Load(),
		CacheHits: e.cacheHits.Load(), WorkerDrops: e.workerDrops.Load(), SocketDrops: e.socketDrops.Load(),
		ActiveTransactions: uint64(active), TransactionCollisions: e.transactionCollisions.Load(),
		InflightDuplicates: e.inflightDuplicates.Load(), InflightReplays: e.inflightReplays.Load(),
	}
}

func (e *Endpoint) Serve(ctx context.Context) error {
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = e.Close()
		case <-stop:
		}
	}()
	defer close(stop)
	buffer := make([]byte, 65_535)
	for {
		n, peer, dropped, err := e.reader.ReadFromUDPAddrPort(buffer)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read GTPv2-C datagram: %w", err)
		}
		e.socketDrops.Add(dropped)
		e.received.Add(1)
		messages, err := gtpv2.ParseMessages(buffer[:n])
		if err != nil {
			e.malformed.Add(1)
			continue
		}
		peer = canonical(peer)
		for _, message := range messages {
			e.dispatch(ctx, peer, message)
		}
	}
}

func (e *Endpoint) Close() error {
	var result error
	e.closeOnce.Do(func() {
		close(e.closed)
		result = e.conn.Close()
	})
	if errors.Is(result, net.ErrClosed) {
		return nil
	}
	return result
}

func (e *Endpoint) Do(ctx context.Context, peer netip.AddrPort, request gtpv2.Message) (gtpv2.Message, error) {
	expected, ok := ExpectedResponseType(request.Header.MessageType)
	if !ok {
		return gtpv2.Message{}, fmt.Errorf("%w: %d", ErrUnsupportedRequest, request.Header.MessageType)
	}
	peer = canonical(peer)
	if !peer.Addr().IsValid() || peer.Port() == 0 {
		return gtpv2.Message{}, errors.New("gtpv2 transport: remote address and port are required")
	}
	request = request.Clone()
	request.Header.Piggybacked = false

	var key transactionKey
	var pending pendingTransaction
	registered := false
	for attempt := 0; attempt < 128; attempt++ {
		key = transactionKey{peer: peer, sequence: e.allocateSequence()}
		pending = pendingTransaction{expectedType: expected, response: make(chan gtpv2.Message, 1)}
		e.pendingMu.Lock()
		if _, exists := e.pending[key]; !exists {
			e.pending[key] = pending
			registered = true
		}
		e.pendingMu.Unlock()
		if registered {
			request.Header.SequenceNumber = key.sequence
			break
		}
	}
	if !registered {
		e.transactionCollisions.Add(1)
		return gtpv2.Message{}, ErrTransactionCollision
	}
	defer func() {
		e.pendingMu.Lock()
		delete(e.pending, key)
		e.pendingMu.Unlock()
	}()

	wire, err := request.MarshalBinary()
	if err != nil {
		return gtpv2.Message{}, err
	}
	for attempt := 0; attempt <= e.config.MaxRetransmits; attempt++ {
		select {
		case <-e.closed:
			return gtpv2.Message{}, ErrClosed
		default:
		}
		if _, err := e.conn.WriteToUDPAddrPort(wire, peer); err != nil {
			if errors.Is(err, net.ErrClosed) {
				return gtpv2.Message{}, ErrClosed
			}
			return gtpv2.Message{}, fmt.Errorf("send GTPv2-C request: %w", err)
		}
		e.sent.Add(1)
		if attempt > 0 {
			e.retransmitted.Add(1)
		}
		timer := time.NewTimer(e.config.RetransmitTimeout)
		select {
		case response := <-pending.response:
			stopTimer(timer)
			return response, nil
		case <-ctx.Done():
			stopTimer(timer)
			return gtpv2.Message{}, ctx.Err()
		case <-e.closed:
			stopTimer(timer)
			return gtpv2.Message{}, ErrClosed
		case <-timer.C:
		}
	}
	e.timedOut.Add(1)
	return gtpv2.Message{}, ErrTimeout
}

func (e *Endpoint) dispatch(ctx context.Context, peer netip.AddrPort, message gtpv2.Message) {
	if IsResponseType(message.Header.MessageType) {
		key := transactionKey{peer: peer, sequence: message.Header.SequenceNumber}
		e.pendingMu.Lock()
		pending, ok := e.pending[key]
		e.pendingMu.Unlock()
		if ok && pending.expectedType == message.Header.MessageType {
			select {
			case pending.response <- message.Clone():
			default:
			}
		}
		return
	}

	cacheKey := requestKey{transactionKey: transactionKey{peer: peer, sequence: message.Header.SequenceNumber}, typ: message.Header.MessageType}
	if wire, ok := e.cached(cacheKey); ok {
		e.cacheHits.Add(1)
		if _, err := e.conn.WriteToUDPAddrPort(wire, peer); err == nil {
			e.sent.Add(1)
		}
		return
	}
	if e.handler == nil {
		return
	}
	e.inflightMu.Lock()
	if inflight, exists := e.inflight[cacheKey]; exists {
		if inflight.replays < maxInflightResponseReplays {
			inflight.replays++
		}
		e.inflightMu.Unlock()
		e.cacheHits.Add(1)
		e.inflightDuplicates.Add(1)
		return
	}
	e.inflight[cacheKey] = &inflightRequest{}
	e.inflightMu.Unlock()
	select {
	case e.workers <- struct{}{}:
		go func() {
			defer func() { <-e.workers }()
			completed := false
			defer func() {
				if !completed {
					e.finishRequest(cacheKey)
				}
			}()
			response, err := e.handler(ctx, peer, message.Clone())
			if err != nil || response == nil {
				return
			}
			response.Header.SequenceNumber = message.Header.SequenceNumber
			response.Header.Piggybacked = false
			wire, err := response.MarshalBinary()
			if err != nil {
				return
			}
			e.putCached(cacheKey, wire)
			responses := e.completeRequest(cacheKey)
			completed = true
			if responses > 1 {
				e.inflightReplays.Add(uint64(responses - 1))
			}
			for responseIndex := 0; responseIndex < responses; responseIndex++ {
				if _, err := e.conn.WriteToUDPAddrPort(wire, peer); err == nil {
					e.sent.Add(1)
				}
			}
		}()
	default:
		e.finishRequest(cacheKey)
		e.workerDrops.Add(1)
	}
}

func (e *Endpoint) completeRequest(key requestKey) int {
	e.inflightMu.Lock()
	defer e.inflightMu.Unlock()
	responses := 1
	if inflight, exists := e.inflight[key]; exists {
		responses += inflight.replays
	}
	delete(e.inflight, key)
	return responses
}

func (e *Endpoint) finishRequest(key requestKey) {
	e.inflightMu.Lock()
	delete(e.inflight, key)
	e.inflightMu.Unlock()
}

func (e *Endpoint) allocateSequence() uint32 {
	for {
		next := e.next.Add(1) & 0x00ff_ffff
		if next != 0 {
			return next
		}
	}
}

func (e *Endpoint) cached(key requestKey) ([]byte, bool) {
	return e.cache.Get(key)
}

func (e *Endpoint) putCached(key requestKey, wire []byte) {
	e.cache.Put(key, wire)
}

func stopTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

func canonical(addr netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
}

func IsResponseType(messageType uint8) bool {
	switch messageType {
	case gtpv2.MessageEchoResponse, gtpv2.MessageVersionNotSupported,
		gtpv2.MessageCreateSessionResponse, gtpv2.MessageModifyBearerResponse,
		gtpv2.MessageDeleteSessionResponse, gtpv2.MessageCreateBearerResponse,
		gtpv2.MessageUpdateBearerResponse, gtpv2.MessageDeleteBearerResponse,
		gtpv2.MessageReleaseAccessBearersResponse, gtpv2.MessageDownlinkDataNotificationAck:
		return true
	default:
		return false
	}
}

func ExpectedResponseType(requestType uint8) (uint8, bool) {
	switch requestType {
	case gtpv2.MessageEchoRequest:
		return gtpv2.MessageEchoResponse, true
	case gtpv2.MessageCreateSessionRequest:
		return gtpv2.MessageCreateSessionResponse, true
	case gtpv2.MessageModifyBearerRequest:
		return gtpv2.MessageModifyBearerResponse, true
	case gtpv2.MessageDeleteSessionRequest:
		return gtpv2.MessageDeleteSessionResponse, true
	case gtpv2.MessageCreateBearerRequest:
		return gtpv2.MessageCreateBearerResponse, true
	case gtpv2.MessageUpdateBearerRequest:
		return gtpv2.MessageUpdateBearerResponse, true
	case gtpv2.MessageDeleteBearerRequest:
		return gtpv2.MessageDeleteBearerResponse, true
	case gtpv2.MessageReleaseAccessBearersRequest:
		return gtpv2.MessageReleaseAccessBearersResponse, true
	case gtpv2.MessageDownlinkDataNotification:
		return gtpv2.MessageDownlinkDataNotificationAck, true
	default:
		return 0, false
	}
}
