// Package transport provides bounded PFCP/UDP delivery and transaction handling.
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
	"github.com/lodestarnetworks/cups/pkg/pfcp"
)

var (
	ErrClosed               = errors.New("pfcp transport: endpoint closed")
	ErrTimeout              = errors.New("pfcp transport: transaction timed out")
	ErrUnsupportedRequest   = errors.New("pfcp transport: unsupported request type")
	ErrTransactionCollision = errors.New("pfcp transport: transaction collision")
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

type Handler func(context.Context, netip.AddrPort, pfcp.Message) (*pfcp.Message, error)

type Counters struct {
	Received           uint64
	Sent               uint64
	Malformed          uint64
	Retransmitted      uint64
	TimedOut           uint64
	CacheHits          uint64
	WorkerDrops        uint64
	SocketDrops        uint64
	InflightDuplicates uint64
	InflightReplays    uint64
}

type counterSet struct {
	received           atomic.Uint64
	sent               atomic.Uint64
	malformed          atomic.Uint64
	retransmitted      atomic.Uint64
	timedOut           atomic.Uint64
	cacheHits          atomic.Uint64
	workerDrops        atomic.Uint64
	socketDrops        atomic.Uint64
	inflightDuplicates atomic.Uint64
	inflightReplays    atomic.Uint64
}

type transactionKey struct {
	peer     netip.AddrPort
	sequence uint32
}

type requestKey struct {
	transactionKey
	typ uint8
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

	pendingMu sync.Mutex
	pending   map[transactionKey]pendingTransaction

	cache      *responsecache.Cache[requestKey]
	inflightMu sync.Mutex
	inflight   map[requestKey]*inflightRequest

	metrics   counterSet
	closed    chan struct{}
	closeOnce sync.Once
}

type pendingTransaction struct {
	expectedType uint8
	response     chan pfcp.Message
}

func Listen(local netip.AddrPort, handler Handler, config Config) (*Endpoint, error) {
	if !local.Addr().IsValid() {
		return nil, errors.New("pfcp transport: local address is required")
	}
	if config.RetransmitTimeout <= 0 || config.MaxRetransmits < 0 || config.MaxWorkers <= 0 || config.ResponseCacheSize < 0 || config.ResponseCacheTTL < 0 || config.SocketBufferBytes < 0 {
		return nil, errors.New("pfcp transport: invalid configuration")
	}
	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(local))
	if err != nil {
		return nil, fmt.Errorf("listen PFCP on %s: %w", local, err)
	}
	if config.SocketBufferBytes > 0 {
		if err := conn.SetReadBuffer(config.SocketBufferBytes); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("size PFCP receive buffer: %w", err)
		}
		if err := conn.SetWriteBuffer(config.SocketBufferBytes); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("size PFCP send buffer: %w", err)
		}
	}
	reader, err := udpstats.NewReader(conn)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("enable PFCP receive-queue accounting: %w", err)
	}
	var seed [4]byte
	if _, err := rand.Read(seed[:]); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("seed PFCP sequence number: %w", err)
	}
	e := &Endpoint{
		conn:     conn,
		reader:   reader,
		handler:  handler,
		config:   config,
		workers:  make(chan struct{}, config.MaxWorkers),
		pending:  make(map[transactionKey]pendingTransaction),
		cache:    responsecache.New[requestKey](config.ResponseCacheSize, config.ResponseCacheTTL),
		inflight: make(map[requestKey]*inflightRequest),
		closed:   make(chan struct{}),
	}
	e.next.Store(binary.BigEndian.Uint32(seed[:]) & 0x00ff_ffff)
	return e, nil
}

func (e *Endpoint) LocalAddr() netip.AddrPort {
	return e.conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

func (e *Endpoint) Counters() Counters {
	return Counters{
		Received:           e.metrics.received.Load(),
		Sent:               e.metrics.sent.Load(),
		Malformed:          e.metrics.malformed.Load(),
		Retransmitted:      e.metrics.retransmitted.Load(),
		TimedOut:           e.metrics.timedOut.Load(),
		CacheHits:          e.metrics.cacheHits.Load(),
		WorkerDrops:        e.metrics.workerDrops.Load(),
		SocketDrops:        e.metrics.socketDrops.Load(),
		InflightDuplicates: e.metrics.inflightDuplicates.Load(),
		InflightReplays:    e.metrics.inflightReplays.Load(),
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
			return fmt.Errorf("read PFCP datagram: %w", err)
		}
		e.metrics.socketDrops.Add(dropped)
		e.metrics.received.Add(1)
		messages, err := pfcp.ParseMessages(buffer[:n])
		if err != nil {
			e.metrics.malformed.Add(1)
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

func (e *Endpoint) Do(ctx context.Context, peer netip.AddrPort, request pfcp.Message) (pfcp.Message, error) {
	expected, ok := ExpectedResponseType(request.Header.MessageType)
	if !ok {
		return pfcp.Message{}, fmt.Errorf("%w: %d", ErrUnsupportedRequest, request.Header.MessageType)
	}
	peer = canonical(peer)
	if !peer.Addr().IsValid() || peer.Port() == 0 {
		return pfcp.Message{}, errors.New("pfcp transport: remote address and port are required")
	}

	request = request.Clone()
	request.Header.FollowOn = false
	var key transactionKey
	var pending pendingTransaction
	registered := false
	for attempt := 0; attempt < 128; attempt++ {
		sequence := e.allocateSequence()
		key = transactionKey{peer: peer, sequence: sequence}
		pending = pendingTransaction{expectedType: expected, response: make(chan pfcp.Message, 1)}
		e.pendingMu.Lock()
		if _, exists := e.pending[key]; !exists {
			e.pending[key] = pending
			registered = true
		}
		e.pendingMu.Unlock()
		if registered {
			request.Header.SequenceNumber = sequence
			break
		}
	}
	if !registered {
		return pfcp.Message{}, ErrTransactionCollision
	}
	defer func() {
		e.pendingMu.Lock()
		delete(e.pending, key)
		e.pendingMu.Unlock()
	}()

	wire, err := request.MarshalBinary()
	if err != nil {
		return pfcp.Message{}, err
	}
	for attempt := 0; attempt <= e.config.MaxRetransmits; attempt++ {
		select {
		case <-e.closed:
			return pfcp.Message{}, ErrClosed
		default:
		}
		if _, err := e.conn.WriteToUDPAddrPort(wire, peer); err != nil {
			if errors.Is(err, net.ErrClosed) {
				return pfcp.Message{}, ErrClosed
			}
			return pfcp.Message{}, fmt.Errorf("send PFCP request: %w", err)
		}
		e.metrics.sent.Add(1)
		if attempt > 0 {
			e.metrics.retransmitted.Add(1)
		}
		timer := time.NewTimer(e.config.RetransmitTimeout)
		select {
		case response := <-pending.response:
			if !timer.Stop() {
				<-timer.C
			}
			return response, nil
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return pfcp.Message{}, ctx.Err()
		case <-e.closed:
			if !timer.Stop() {
				<-timer.C
			}
			return pfcp.Message{}, ErrClosed
		case <-timer.C:
		}
	}
	e.metrics.timedOut.Add(1)
	return pfcp.Message{}, ErrTimeout
}

func (e *Endpoint) dispatch(ctx context.Context, peer netip.AddrPort, message pfcp.Message) {
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
		e.metrics.cacheHits.Add(1)
		if _, err := e.conn.WriteToUDPAddrPort(wire, peer); err == nil {
			e.metrics.sent.Add(1)
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
		e.metrics.cacheHits.Add(1)
		e.metrics.inflightDuplicates.Add(1)
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
			response.Header.FollowOn = false
			wire, err := response.MarshalBinary()
			if err != nil {
				return
			}
			e.putCached(cacheKey, wire)
			responses := e.completeRequest(cacheKey)
			completed = true
			if responses > 1 {
				e.metrics.inflightReplays.Add(uint64(responses - 1))
			}
			for responseIndex := 0; responseIndex < responses; responseIndex++ {
				if _, err := e.conn.WriteToUDPAddrPort(wire, peer); err == nil {
					e.metrics.sent.Add(1)
				}
			}
		}()
	default:
		e.finishRequest(cacheKey)
		e.metrics.workerDrops.Add(1)
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

func canonical(addr netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
}

func IsResponseType(messageType uint8) bool {
	switch messageType {
	case pfcp.MessageHeartbeatResponse,
		pfcp.MessageAssociationSetupResponse,
		pfcp.MessageAssociationUpdateResponse,
		pfcp.MessageAssociationReleaseResponse,
		pfcp.MessageVersionNotSupportedResponse,
		pfcp.MessageNodeReportResponse,
		pfcp.MessageSessionSetDeletionResponse,
		pfcp.MessageSessionEstablishmentResponse,
		pfcp.MessageSessionModificationResponse,
		pfcp.MessageSessionDeletionResponse,
		pfcp.MessageSessionReportResponse:
		return true
	default:
		return false
	}
}

func ExpectedResponseType(requestType uint8) (uint8, bool) {
	switch requestType {
	case pfcp.MessageHeartbeatRequest:
		return pfcp.MessageHeartbeatResponse, true
	case pfcp.MessageAssociationSetupRequest:
		return pfcp.MessageAssociationSetupResponse, true
	case pfcp.MessageAssociationUpdateRequest:
		return pfcp.MessageAssociationUpdateResponse, true
	case pfcp.MessageAssociationReleaseRequest:
		return pfcp.MessageAssociationReleaseResponse, true
	case pfcp.MessageNodeReportRequest:
		return pfcp.MessageNodeReportResponse, true
	case pfcp.MessageSessionSetDeletionRequest:
		return pfcp.MessageSessionSetDeletionResponse, true
	case pfcp.MessageSessionEstablishmentRequest:
		return pfcp.MessageSessionEstablishmentResponse, true
	case pfcp.MessageSessionModificationRequest:
		return pfcp.MessageSessionModificationResponse, true
	case pfcp.MessageSessionDeletionRequest:
		return pfcp.MessageSessionDeletionResponse, true
	case pfcp.MessageSessionReportRequest:
		return pfcp.MessageSessionReportResponse, true
	default:
		return 0, false
	}
}
