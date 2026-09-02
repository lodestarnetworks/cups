package epc

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	gtptransport "github.com/lodestarnetworks/cups/internal/gtpv2/transport"
	"github.com/lodestarnetworks/cups/internal/udpstats"
	"github.com/lodestarnetworks/cups/pkg/gtpu"
	"github.com/lodestarnetworks/cups/pkg/gtpv2"
)

const (
	serviceUplinkPort                = uint16(40_000)
	maximumServiceThroughputDuration = 24 * time.Hour
	serviceSequenceWindowPackets     = 65_536
)

// ServiceCUPSConfig addresses already-running SGW-C/U and PGW-C/U processes.
// The caller owns the synthetic MME, eNodeB, and external-host addresses.
type ServiceCUPSConfig struct {
	MMEControl             netip.AddrPort
	SGWS11                 netip.AddrPort
	ENBUser                netip.AddrPort
	ExternalUser           netip.AddrPort
	IMSI                   string
	APN                    string
	EBI                    uint8
	Timeout                time.Duration
	Transport              gtptransport.Config
	SocketBufferBytes      int
	HoldAfterModify        time.Duration
	HoldAfterData          time.Duration
	ThroughputDuration     time.Duration
	ThroughputDirection    string
	PayloadSize            int
	TargetPacketsPerSecond int
	PacketBatchSize        int
	MMEControlTEID         uint32
	ENodeBTEID             uint32
}

type ServiceCUPSResult struct {
	MeasurementScope            string           `json:"measurementScope"`
	Subscriber                  string           `json:"subscriber"`
	APN                         string           `json:"apn"`
	EBI                         uint8            `json:"ebi"`
	UEIPv4                      string           `json:"ueIpv4"`
	SGWS11TEID                  uint32           `json:"sgwS11Teid"`
	SGWAccessTEID               uint32           `json:"sgwAccessTeid"`
	ENodeBTEID                  uint32           `json:"enodebTeid"`
	CreateSessionMilliseconds   float64          `json:"createSessionMilliseconds"`
	ModifyBearerMilliseconds    float64          `json:"modifyBearerMilliseconds"`
	UplinkMilliseconds          float64          `json:"uplinkMilliseconds"`
	DownlinkMilliseconds        float64          `json:"downlinkMilliseconds"`
	DeleteSessionMilliseconds   float64          `json:"deleteSessionMilliseconds"`
	UplinkPayloadBytes          int              `json:"uplinkPayloadBytes"`
	DownlinkPayloadBytes        int              `json:"downlinkPayloadBytes"`
	HoldAfterModifyMilliseconds float64          `json:"holdAfterModifyMilliseconds"`
	HoldAfterDataMilliseconds   float64          `json:"holdAfterDataMilliseconds"`
	ThroughputDirection         string           `json:"throughputDirection,omitempty"`
	UplinkThroughput            ThroughputResult `json:"uplinkThroughput"`
	DownlinkThroughput          ThroughputResult `json:"downlinkThroughput"`
	ElapsedMilliseconds         float64          `json:"elapsedMilliseconds"`
}

// RunServiceCUPS performs a black-box session and bidirectional packet test
// against four already-running CUPS services. It does not start gateway code
// in-process and always attempts to detach an accepted session on failure.
func RunServiceCUPS(ctx context.Context, config ServiceCUPSConfig) (ServiceCUPSResult, error) {
	started := time.Now()
	if config.SocketBufferBytes == 0 {
		config.SocketBufferBytes = 16 << 20
	}
	if config.PayloadSize == 0 {
		config.PayloadSize = 1200
	}
	if config.ThroughputDirection == "" {
		config.ThroughputDirection = "both"
	}
	if config.PacketBatchSize == 0 {
		config.PacketBatchSize = 128
	}
	if config.MMEControlTEID == 0 {
		config.MMEControlTEID = 0x7a00_0001
	}
	if config.ENodeBTEID == 0 {
		config.ENodeBTEID = 0x7b00_0001
	}
	if err := validateServiceCUPS(config); err != nil {
		return ServiceCUPSResult{}, err
	}

	mmeHandler := &mmePeer{
		enodebIP:  config.ENBUser.Addr(),
		dedicated: make(map[uint8]uint32),
		ddn:       make(chan uint8, 4),
	}
	mme, err := gtptransport.Listen(config.MMEControl, mmeHandler.handle, config.Transport)
	if err != nil {
		return ServiceCUPSResult{}, fmt.Errorf("listen service-test MME: %w", err)
	}
	defer mme.Close()
	enodeb, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(config.ENBUser))
	if err != nil {
		return ServiceCUPSResult{}, fmt.Errorf("listen service-test eNodeB: %w", err)
	}
	defer enodeb.Close()
	if err := configureUDPSocket(enodeb, config.SocketBufferBytes); err != nil {
		return ServiceCUPSResult{}, fmt.Errorf("configure service-test eNodeB: %w", err)
	}
	external, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(config.ExternalUser))
	if err != nil {
		return ServiceCUPSResult{}, fmt.Errorf("listen service-test external host: %w", err)
	}
	defer external.Close()
	if err := configureUDPSocket(external, config.SocketBufferBytes); err != nil {
		return ServiceCUPSResult{}, fmt.Errorf("configure service-test external host: %w", err)
	}

	child, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = mme.Serve(child) }()

	labConfig := Config{
		MMEControl: config.MMEControl,
		SGWS11:     config.SGWS11,
		ENBUser:    config.ENBUser,
		IMSI:       config.IMSI,
		APN:        config.APN,
		EBI:        config.EBI,
	}
	mmeTEID := config.MMEControlTEID
	enodebTEID := config.ENodeBTEID
	create, err := createRequest(labConfig, mmeTEID)
	if err != nil {
		return ServiceCUPSResult{}, err
	}
	procedureStarted := time.Now()
	response, err := do(ctx, config.Timeout, mme, config.SGWS11, create)
	createMilliseconds := milliseconds(time.Since(procedureStarted))
	if err != nil {
		return ServiceCUPSResult{}, fmt.Errorf("service CUPS Create Session: %w", err)
	}
	if err := accepted(response); err != nil {
		return ServiceCUPSResult{}, fmt.Errorf("service CUPS Create Session: %w", err)
	}
	sgwControl, err := findFTEID(response.IEs, 0)
	if err != nil || sgwControl.InterfaceType != gtpv2.InterfaceS11SGWGTPC {
		return ServiceCUPSResult{}, errors.New("service CUPS Create Session returned an invalid SGW S11 F-TEID")
	}
	mmeHandler.setSGWControlTEID(sgwControl.TEID)
	createBearer, err := bearerChildren(response)
	if err != nil {
		return ServiceCUPSResult{}, err
	}
	sgwAccess, err := findFTEID(createBearer, 0)
	if err != nil || sgwAccess.InterfaceType != gtpv2.InterfaceS1USGWGTPU {
		return ServiceCUPSResult{}, errors.New("service CUPS Create Session returned an invalid SGW S1-U F-TEID")
	}
	paaIE, ok := response.Find(gtpv2.IEPAA, 0)
	if !ok {
		return ServiceCUPSResult{}, errors.New("service CUPS Create Session omitted the UE IPv4 PAA")
	}
	ueIPv4, err := paaIE.PAAIPv4()
	if err != nil {
		return ServiceCUPSResult{}, fmt.Errorf("service CUPS UE IPv4 PAA: %w", err)
	}

	deleteRequest := gtpv2.Message{}
	sessionCreated := true
	sessionDeleted := false
	defer func() {
		if !sessionCreated || sessionDeleted {
			return
		}
		cleanupContext, stop := context.WithTimeout(context.Background(), config.Timeout)
		defer stop()
		_, _ = mme.Do(cleanupContext, config.SGWS11, deleteRequest)
	}()
	ebiIE, _ := gtpv2.NewEBIIE(config.EBI, 0)
	deleteRequest = gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageDeleteSessionRequest, TEID: sgwControl.TEID},
		IEs:    []gtpv2.IE{ebiIE},
	}

	modify, err := modifyRequest(labConfig, sgwControl.TEID, enodebTEID)
	if err != nil {
		return ServiceCUPSResult{}, err
	}
	procedureStarted = time.Now()
	response, err = do(ctx, config.Timeout, mme, config.SGWS11, modify)
	modifyMilliseconds := milliseconds(time.Since(procedureStarted))
	if err != nil {
		return ServiceCUPSResult{}, fmt.Errorf("service CUPS Modify Bearer: %w", err)
	}
	if err := accepted(response); err != nil {
		return ServiceCUPSResult{}, fmt.Errorf("service CUPS Modify Bearer: %w", err)
	}
	if config.HoldAfterModify > 0 {
		timer := time.NewTimer(config.HoldAfterModify)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ServiceCUPSResult{}, ctx.Err()
		case <-timer.C:
		}
	}

	uplinkPayload := []byte("lodestar-service-cups-uplink")
	uplinkPacket, err := buildIPv4UDP(
		ueIPv4, config.ExternalUser.Addr(), serviceUplinkPort, config.ExternalUser.Port(), uplinkPayload,
	)
	if err != nil {
		return ServiceCUPSResult{}, err
	}
	packetStarted := time.Now()
	if err := sendGPDU(enodeb, netip.AddrPortFrom(sgwAccess.IPv4, 2152), sgwAccess.TEID, uplinkPacket); err != nil {
		return ServiceCUPSResult{}, fmt.Errorf("service CUPS uplink send: %w", err)
	}
	if err := receiveExternalUDP(external, ueIPv4, serviceUplinkPort, uplinkPayload, config.Timeout); err != nil {
		return ServiceCUPSResult{}, fmt.Errorf("service CUPS uplink receive: %w", err)
	}
	uplinkMilliseconds := milliseconds(time.Since(packetStarted))

	downlinkPayload := []byte("lodestar-service-cups-downlink")
	packetStarted = time.Now()
	if _, err := external.WriteToUDPAddrPort(downlinkPayload, netip.AddrPortFrom(ueIPv4, serviceUplinkPort)); err != nil {
		return ServiceCUPSResult{}, fmt.Errorf("service CUPS downlink send: %w", err)
	}
	if err := receiveServiceDownlink(
		enodeb, enodebTEID, config.ExternalUser.Addr(), ueIPv4,
		config.ExternalUser.Port(), serviceUplinkPort, downlinkPayload, config.Timeout,
	); err != nil {
		return ServiceCUPSResult{}, fmt.Errorf("service CUPS downlink receive: %w", err)
	}
	downlinkMilliseconds := milliseconds(time.Since(packetStarted))
	uplinkThroughput, downlinkThroughput := ThroughputResult{}, ThroughputResult{}
	if config.ThroughputDuration > 0 {
		uplinkThroughput, downlinkThroughput, err = measureServiceCUPSThroughput(
			ctx, enodeb, external, netip.AddrPortFrom(sgwAccess.IPv4, 2152),
			sgwAccess.TEID, enodebTEID, ueIPv4, config,
		)
		if err != nil {
			return ServiceCUPSResult{}, fmt.Errorf("service CUPS throughput: %w", err)
		}
	}
	if config.HoldAfterData > 0 {
		timer := time.NewTimer(config.HoldAfterData)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ServiceCUPSResult{}, ctx.Err()
		case <-timer.C:
		}
	}

	procedureStarted = time.Now()
	response, err = do(ctx, config.Timeout, mme, config.SGWS11, deleteRequest)
	deleteMilliseconds := milliseconds(time.Since(procedureStarted))
	if err != nil {
		return ServiceCUPSResult{}, fmt.Errorf("service CUPS Delete Session: %w", err)
	}
	if err := accepted(response); err != nil {
		return ServiceCUPSResult{}, fmt.Errorf("service CUPS Delete Session: %w", err)
	}
	sessionDeleted = true

	return ServiceCUPSResult{
		MeasurementScope:            "running four-component CUPS services; local synthetic MME/eNodeB/external host",
		Subscriber:                  maskIMSI(config.IMSI),
		APN:                         config.APN,
		EBI:                         config.EBI,
		UEIPv4:                      ueIPv4.String(),
		SGWS11TEID:                  sgwControl.TEID,
		SGWAccessTEID:               sgwAccess.TEID,
		ENodeBTEID:                  enodebTEID,
		CreateSessionMilliseconds:   createMilliseconds,
		ModifyBearerMilliseconds:    modifyMilliseconds,
		UplinkMilliseconds:          uplinkMilliseconds,
		DownlinkMilliseconds:        downlinkMilliseconds,
		DeleteSessionMilliseconds:   deleteMilliseconds,
		UplinkPayloadBytes:          len(uplinkPayload),
		DownlinkPayloadBytes:        len(downlinkPayload),
		HoldAfterModifyMilliseconds: milliseconds(config.HoldAfterModify),
		HoldAfterDataMilliseconds:   milliseconds(config.HoldAfterData),
		ThroughputDirection:         config.ThroughputDirection,
		UplinkThroughput:            uplinkThroughput,
		DownlinkThroughput:          downlinkThroughput,
		ElapsedMilliseconds:         milliseconds(time.Since(started)),
	}, nil
}

func validateServiceCUPS(config ServiceCUPSConfig) error {
	for name, value := range map[string]netip.AddrPort{
		"MME control":   config.MMEControl,
		"SGW S11":       config.SGWS11,
		"eNodeB user":   config.ENBUser,
		"external user": config.ExternalUser,
	} {
		if !value.Addr().Is4() || value.Port() == 0 {
			return fmt.Errorf("service CUPS: %s requires an IPv4 address and port", name)
		}
	}
	if config.ENBUser.Port() != 2152 {
		return errors.New("service CUPS: synthetic eNodeB must use UDP 2152")
	}
	if config.IMSI == "" || config.APN == "" || config.EBI < 5 || config.EBI > 15 || config.Timeout <= 0 {
		return errors.New("service CUPS: IMSI, APN, LTE EBI, and timeout are required")
	}
	if config.SocketBufferBytes < 64<<10 || config.SocketBufferBytes > 1<<30 {
		return errors.New("service CUPS: socket buffer must be between 65536 and 1073741824 bytes")
	}
	if config.HoldAfterModify < 0 || config.HoldAfterModify > time.Minute {
		return errors.New("service CUPS: post-modify hold must be between zero and one minute")
	}
	if config.HoldAfterData < 0 || config.HoldAfterData > time.Minute {
		return errors.New("service CUPS: post-data hold must be between zero and one minute")
	}
	if config.ThroughputDuration < 0 || config.ThroughputDuration > maximumServiceThroughputDuration {
		return errors.New("service CUPS: throughput duration must be between zero and 24 hours")
	}
	if config.ThroughputDuration > 0 && config.ThroughputDuration < 100*time.Millisecond {
		return errors.New("service CUPS: non-zero throughput duration must be at least 100ms")
	}
	if config.ThroughputDirection != "uplink" && config.ThroughputDirection != "downlink" && config.ThroughputDirection != "both" {
		return errors.New("service CUPS: throughput direction must be uplink, downlink, or both")
	}
	if config.PayloadSize < 64 || config.PayloadSize > 1400 {
		return errors.New("service CUPS: throughput inner packet size must be between 64 and 1400 bytes")
	}
	if config.TargetPacketsPerSecond < 0 || config.TargetPacketsPerSecond > 1_000_000 {
		return errors.New("service CUPS: target packet rate must be between zero and 1000000 packets/s per direction")
	}
	if config.PacketBatchSize < 1 || config.PacketBatchSize > 1024 {
		return errors.New("service CUPS: packet batch size must be between 1 and 1024")
	}
	if config.MMEControlTEID == 0 || config.ENodeBTEID == 0 {
		return errors.New("service CUPS: synthetic MME and eNodeB TEIDs must be non-zero")
	}
	return nil
}

type serviceBatchSender func(firstSequence uint64, packets int) (sent int, err error)
type serviceBatchReceiver func(deadline time.Time) (packets int, socketDrops uint64, err error)

type serviceSequenceStats struct {
	unique      uint64
	duplicates  uint64
	outOfOrder  uint64
	tooOld      uint64
	highest     uint64
	initialized bool
}

// serviceSequenceTracker keeps exact duplicate and reordering state for a
// bounded recent window. The fixed-size window avoids memory growth during a
// 24-hour soak while retaining several seconds of history per flow at the
// maximum supported packet rate.
type serviceSequenceTracker struct {
	seen        []uint64
	unique      uint64
	duplicates  uint64
	outOfOrder  uint64
	tooOld      uint64
	highest     uint64
	initialized bool
}

func newServiceSequenceTracker(windowPackets int) *serviceSequenceTracker {
	return &serviceSequenceTracker{seen: make([]uint64, windowPackets)}
}

func (tracker *serviceSequenceTracker) observe(sequence uint64) {
	if len(tracker.seen) == 0 {
		return
	}
	index := sequence % uint64(len(tracker.seen))
	tag := sequence + 1
	if tracker.seen[index] == tag {
		tracker.duplicates++
		return
	}
	if tracker.initialized && sequence <= tracker.highest &&
		tracker.highest-sequence >= uint64(len(tracker.seen)) {
		tracker.tooOld++
		return
	}
	tracker.seen[index] = tag
	tracker.unique++
	if !tracker.initialized {
		tracker.highest = sequence
		tracker.initialized = true
		return
	}
	if sequence < tracker.highest {
		tracker.outOfOrder++
		return
	}
	if sequence > tracker.highest {
		tracker.highest = sequence
	}
}

func (tracker *serviceSequenceTracker) stats() serviceSequenceStats {
	return serviceSequenceStats{
		unique: tracker.unique, duplicates: tracker.duplicates,
		outOfOrder: tracker.outOfOrder, tooOld: tracker.tooOld,
		highest: tracker.highest, initialized: tracker.initialized,
	}
}

func measureServiceCUPSThroughput(
	ctx context.Context,
	enodeb, external *net.UDPConn,
	sgwAccess netip.AddrPort,
	sgwAccessTEID, enodebTEID uint32,
	ueIPv4 netip.Addr,
	config ServiceCUPSConfig,
) (ThroughputResult, ThroughputResult, error) {
	enodebIO, err := udpstats.NewReader(enodeb)
	if err != nil {
		return ThroughputResult{}, ThroughputResult{}, fmt.Errorf("prepare eNodeB batch socket: %w", err)
	}
	externalIO, err := udpstats.NewReader(external)
	if err != nil {
		return ThroughputResult{}, ThroughputResult{}, fmt.Errorf("prepare external-host batch socket: %w", err)
	}
	type directionalResult struct {
		direction string
		value     ThroughputResult
		err       error
	}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan directionalResult, 2)
	directions := 0
	if config.ThroughputDirection == "uplink" || config.ThroughputDirection == "both" {
		directions++
		go func() {
			value, err := measureServiceUplink(
				child, enodebIO, externalIO, external, sgwAccess, sgwAccessTEID, ueIPv4,
				config.ThroughputDuration, config.PayloadSize, config.TargetPacketsPerSecond, config.PacketBatchSize,
			)
			results <- directionalResult{direction: "uplink", value: value, err: err}
		}()
	}
	if config.ThroughputDirection == "downlink" || config.ThroughputDirection == "both" {
		directions++
		go func() {
			value, err := measureServiceDownlink(
				child, externalIO, enodebIO, external, enodebTEID, ueIPv4,
				config.ThroughputDuration, config.PayloadSize, config.TargetPacketsPerSecond, config.PacketBatchSize,
			)
			results <- directionalResult{direction: "downlink", value: value, err: err}
		}()
	}

	uplink, downlink := ThroughputResult{}, ThroughputResult{}
	var firstErr error
	for index := 0; index < directions; index++ {
		result := <-results
		if result.err != nil && firstErr == nil {
			firstErr = fmt.Errorf("%s: %w", result.direction, result.err)
			cancel()
		}
		if result.direction == "uplink" {
			uplink = result.value
		} else {
			downlink = result.value
		}
	}
	return uplink, downlink, firstErr
}

func measureServiceUplink(
	ctx context.Context,
	sender, receiver *udpstats.Reader,
	receiverConn *net.UDPConn,
	destination netip.AddrPort,
	incomingTEID uint32,
	ueIPv4 netip.Addr,
	duration time.Duration,
	innerPacketBytes, targetPPS, batchSize int,
) (ThroughputResult, error) {
	payloadBytes := innerPacketBytes - 28
	wirePackets := make([][]byte, batchSize)
	sequenceOffsets := make([]int, batchSize)
	externalEndpoint := receiverConn.LocalAddr().(*net.UDPAddr).AddrPort()
	for index := range wirePackets {
		payload := serviceThroughputPayload(payloadBytes, uint64(index))
		packet, err := buildIPv4UDP(
			ueIPv4, externalEndpoint.Addr(), serviceUplinkPort, externalEndpoint.Port(), payload,
		)
		if err != nil {
			return ThroughputResult{}, err
		}
		wire, err := gtpu.Marshal(gtpu.Header{
			Version: gtpu.Version, ProtocolType: true, MessageType: gtpu.MessageGPDU, TEID: incomingTEID,
		}, packet)
		if err != nil {
			return ThroughputResult{}, err
		}
		wirePackets[index] = wire
		sequenceOffsets[index] = len(wire) - payloadBytes + 8
	}
	wireBatch, err := udpstats.NewSendBatch(batchSize)
	if err != nil {
		return ThroughputResult{}, err
	}
	send := func(firstSequence uint64, packets int) (int, error) {
		wireBatch.Reset()
		for index := 0; index < packets; index++ {
			wire := wirePackets[index]
			offset := sequenceOffsets[index]
			binary.BigEndian.PutUint64(wire[offset:offset+8], firstSequence+uint64(index))
			if !wireBatch.Append(wire, destination) {
				return 0, errors.New("service CUPS: uplink send batch overflow")
			}
		}
		return sender.WriteBatch(wireBatch)
	}
	receiveBatch, err := receiver.NewBatch(batchSize, 2048)
	if err != nil {
		return ThroughputResult{}, err
	}
	sequences := newServiceSequenceTracker(serviceSequenceWindowPackets)
	receive := func(deadline time.Time) (int, uint64, error) {
		_ = receiver.SetReadDeadline(deadline)
		n, socketDrops, err := receiver.ReadBatch(receiveBatch)
		if err != nil {
			return 0, socketDrops, err
		}
		for index := 0; index < n; index++ {
			datagram := &receiveBatch.Datagrams[index]
			sequence, valid := serviceThroughputSequence(datagram.Buffer[:datagram.N], payloadBytes)
			if datagram.Peer.Addr() != ueIPv4 || datagram.Peer.Port() != serviceUplinkPort || !valid {
				return index, socketDrops, fmt.Errorf("invalid uplink throughput packet from %s", datagram.Peer)
			}
			sequences.observe(sequence)
		}
		return n, socketDrops, nil
	}
	return measureServiceStream(ctx, duration, innerPacketBytes, targetPPS, batchSize, send, receive, sequences)
}

func measureServiceDownlink(
	ctx context.Context,
	sender, receiver *udpstats.Reader,
	senderConn *net.UDPConn,
	expectedTEID uint32,
	ueIPv4 netip.Addr,
	duration time.Duration,
	innerPacketBytes, targetPPS, batchSize int,
) (ThroughputResult, error) {
	payloadBytes := innerPacketBytes - 28
	sourceEndpoint := senderConn.LocalAddr().(*net.UDPAddr).AddrPort()
	sourceIPv4 := sourceEndpoint.Addr()
	payloads := make([][]byte, batchSize)
	for index := range payloads {
		payloads[index] = serviceThroughputPayload(payloadBytes, uint64(index))
	}
	wireBatch, err := udpstats.NewSendBatch(batchSize)
	if err != nil {
		return ThroughputResult{}, err
	}
	destination := netip.AddrPortFrom(ueIPv4, serviceUplinkPort)
	send := func(firstSequence uint64, packets int) (int, error) {
		wireBatch.Reset()
		for index := 0; index < packets; index++ {
			payload := payloads[index]
			binary.BigEndian.PutUint64(payload[8:16], firstSequence+uint64(index))
			if !wireBatch.Append(payload, destination) {
				return 0, errors.New("service CUPS: downlink send batch overflow")
			}
		}
		return sender.WriteBatch(wireBatch)
	}
	receiveBatch, err := receiver.NewBatch(batchSize, 2048)
	if err != nil {
		return ThroughputResult{}, err
	}
	sequences := newServiceSequenceTracker(serviceSequenceWindowPackets)
	receive := func(deadline time.Time) (int, uint64, error) {
		_ = receiver.SetReadDeadline(deadline)
		n, socketDrops, err := receiver.ReadBatch(receiveBatch)
		if err != nil {
			return 0, socketDrops, err
		}
		for index := 0; index < n; index++ {
			datagram := &receiveBatch.Datagrams[index]
			header, packet, parseErr := gtpu.Parse(datagram.Buffer[:datagram.N])
			if parseErr != nil || header.MessageType != gtpu.MessageGPDU || header.TEID != expectedTEID {
				return index, socketDrops, errors.New("invalid downlink GTP-U packet during throughput run")
			}
			actualSource, actualDestination, sourcePort, destinationPort, payload, parseErr := parseIPv4UDP(packet)
			if parseErr != nil {
				return index, socketDrops, parseErr
			}
			sequence, valid := serviceThroughputSequence(payload, payloadBytes)
			if len(packet) != innerPacketBytes || actualSource != sourceIPv4 || actualDestination != ueIPv4 ||
				sourcePort != sourceEndpoint.Port() || destinationPort != serviceUplinkPort || !valid {
				return index, socketDrops, errors.New("invalid downlink inner packet during throughput run")
			}
			sequences.observe(sequence)
		}
		return n, socketDrops, nil
	}
	return measureServiceStream(ctx, duration, innerPacketBytes, targetPPS, batchSize, send, receive, sequences)
}

func measureServiceStream(
	ctx context.Context,
	duration time.Duration,
	innerPacketBytes, targetPPS, batchSize int,
	send serviceBatchSender,
	receive serviceBatchReceiver,
	sequences *serviceSequenceTracker,
) (ThroughputResult, error) {
	type receiveResult struct {
		packets     uint64
		socketDrops uint64
		err         error
	}
	sendingDone := make(chan struct{})
	received := make(chan receiveResult, 1)
	go func() {
		var packets, socketDrops uint64
		for {
			n, dropped, err := receive(time.Now().Add(100 * time.Millisecond))
			packets += uint64(n)
			socketDrops += dropped
			if err == nil {
				continue
			}
			var netError net.Error
			if errors.As(err, &netError) && netError.Timeout() {
				select {
				case <-sendingDone:
					received <- receiveResult{packets: packets, socketDrops: socketDrops}
					return
				default:
					continue
				}
			}
			received <- receiveResult{packets: packets, socketDrops: socketDrops, err: err}
			return
		}
	}()

	started := time.Now()
	end := started.Add(duration)
	var sent uint64
	sendSome := func(packets int) error {
		accepted, err := send(sent, packets)
		sent += uint64(accepted)
		if err != nil {
			return err
		}
		if accepted != packets {
			return fmt.Errorf("service CUPS: short batch write accepted %d of %d packets", accepted, packets)
		}
		return nil
	}
	var sendErr error
	if targetPPS == 0 {
		for time.Now().Before(end) {
			select {
			case <-ctx.Done():
				sendErr = ctx.Err()
			default:
				sendErr = sendSome(batchSize)
			}
			if sendErr != nil {
				break
			}
		}
	} else {
		ticker := time.NewTicker(250 * time.Microsecond)
		lastTick := started
		tokens := float64(0)
	paceLoop:
		for {
			select {
			case <-ctx.Done():
				sendErr = ctx.Err()
				break paceLoop
			case tick := <-ticker.C:
				if !tick.Before(end) {
					break paceLoop
				}
				tokens += tick.Sub(lastTick).Seconds() * float64(targetPPS)
				lastTick = tick
				packets := int(tokens)
				tokens -= float64(packets)
				for packets > 0 {
					if !time.Now().Before(end) {
						break paceLoop
					}
					batch := packets
					if batch > batchSize {
						batch = batchSize
					}
					if sendErr = sendSome(batch); sendErr != nil {
						break paceLoop
					}
					packets -= batch
				}
			}
		}
		ticker.Stop()
	}
	elapsed := time.Since(started)
	close(sendingDone)
	var receiveValue receiveResult
	select {
	case receiveValue = <-received:
	case <-ctx.Done():
		return ThroughputResult{}, ctx.Err()
	case <-time.After(2 * time.Second):
		return ThroughputResult{}, errors.New("timed out draining service throughput receiver")
	}
	if receiveValue.err != nil {
		return ThroughputResult{}, receiveValue.err
	}
	if sendErr != nil {
		return ThroughputResult{}, sendErr
	}
	sequenceStats := sequences.stats()
	if sequenceStats.unique > sent || (sequenceStats.initialized && sequenceStats.highest >= sent) {
		return ThroughputResult{}, fmt.Errorf(
			"service CUPS: received invalid sequence state unique=%d highest=%d sent=%d",
			sequenceStats.unique, sequenceStats.highest, sent,
		)
	}
	lost := uint64(0)
	if sequenceStats.unique < sent {
		lost = sent - sequenceStats.unique
	}
	seconds := elapsed.Seconds()
	lossPercent := float64(0)
	if sent > 0 {
		lossPercent = float64(lost) / float64(sent) * 100
	}
	return ThroughputResult{
		DurationSeconds: seconds, PayloadBytes: innerPacketBytes, TargetPacketsPerSecond: targetPPS,
		SentPackets: sent, ReceivedDatagrams: receiveValue.packets, ReceivedPackets: sequenceStats.unique,
		DuplicatePackets: sequenceStats.duplicates, OutOfOrderPackets: sequenceStats.outOfOrder,
		SequenceTooOldPackets: sequenceStats.tooOld, HighestSequence: sequenceStats.highest,
		ReceiverSocketDroppedPackets: receiveValue.socketDrops, LostPackets: lost,
		LossPercent: lossPercent, PacketsPerSecond: float64(sequenceStats.unique) / seconds,
		TargetMbps: float64(targetPPS*innerPacketBytes*8) / 1_000_000,
		Mbps:       float64(sequenceStats.unique*uint64(innerPacketBytes)*8) / seconds / 1_000_000,
	}, nil
}

func serviceThroughputPayload(size int, sequence uint64) []byte {
	payload := make([]byte, size)
	copy(payload, "LSCUPS01")
	binary.BigEndian.PutUint64(payload[8:16], sequence)
	for index := 16; index < len(payload); index++ {
		payload[index] = byte(index + int(sequence))
	}
	return payload
}

func validServiceThroughputPayload(payload []byte, size int) bool {
	_, valid := serviceThroughputSequence(payload, size)
	return valid
}

func serviceThroughputSequence(payload []byte, size int) (uint64, bool) {
	if len(payload) != size || len(payload) < 16 || string(payload[:8]) != "LSCUPS01" {
		return 0, false
	}
	return binary.BigEndian.Uint64(payload[8:16]), true
}

func buildIPv4UDP(source, destination netip.Addr, sourcePort, destinationPort uint16, payload []byte) ([]byte, error) {
	if !source.Is4() || !destination.Is4() || sourcePort == 0 || destinationPort == 0 || len(payload) > 65_507 {
		return nil, errors.New("service CUPS: invalid IPv4 UDP packet fields")
	}
	packet := make([]byte, 20+8+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[4:6], 0x4c53)
	binary.BigEndian.PutUint16(packet[6:8], 0x4000)
	packet[8] = 64
	packet[9] = 17
	sourceRaw, destinationRaw := source.As4(), destination.As4()
	copy(packet[12:16], sourceRaw[:])
	copy(packet[16:20], destinationRaw[:])
	binary.BigEndian.PutUint16(packet[10:12], ipv4HeaderChecksum(packet[:20]))
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], destinationPort)
	binary.BigEndian.PutUint16(packet[24:26], uint16(8+len(payload)))
	copy(packet[28:], payload)
	return packet, nil
}

func ipv4HeaderChecksum(header []byte) uint16 {
	var sum uint32
	for offset := 0; offset+1 < len(header); offset += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[offset : offset+2]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func receiveExternalUDP(conn *net.UDPConn, expectedSource netip.Addr, expectedPort uint16, expectedPayload []byte, timeout time.Duration) error {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buffer := make([]byte, 65_535)
	n, source, err := conn.ReadFromUDPAddrPort(buffer)
	if err != nil {
		return err
	}
	if source.Addr() != expectedSource || source.Port() != expectedPort || string(buffer[:n]) != string(expectedPayload) {
		return fmt.Errorf("unexpected external UDP packet source=%s payload=%x", source, buffer[:n])
	}
	return nil
}

func receiveServiceDownlink(conn *net.UDPConn, expectedTEID uint32, source, destination netip.Addr, sourcePort, destinationPort uint16, expectedPayload []byte, timeout time.Duration) error {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buffer := make([]byte, 65_535)
	n, _, err := conn.ReadFromUDPAddrPort(buffer)
	if err != nil {
		return err
	}
	header, packet, err := gtpu.Parse(buffer[:n])
	if err != nil {
		return err
	}
	if header.MessageType != gtpu.MessageGPDU || header.TEID != expectedTEID {
		return fmt.Errorf("unexpected downlink GTP-U header type=%d TEID=%#x", header.MessageType, header.TEID)
	}
	actualSource, actualDestination, actualSourcePort, actualDestinationPort, payload, err := parseIPv4UDP(packet)
	if err != nil {
		return err
	}
	if actualSource != source || actualDestination != destination || actualSourcePort != sourcePort ||
		actualDestinationPort != destinationPort || string(payload) != string(expectedPayload) {
		return fmt.Errorf("unexpected downlink IPv4 UDP packet %s:%d -> %s:%d payload=%x",
			actualSource, actualSourcePort, actualDestination, actualDestinationPort, payload)
	}
	return nil
}

func parseIPv4UDP(packet []byte) (netip.Addr, netip.Addr, uint16, uint16, []byte, error) {
	if len(packet) < 28 || packet[0]>>4 != 4 {
		return netip.Addr{}, netip.Addr{}, 0, 0, nil, errors.New("service CUPS: malformed IPv4 UDP packet")
	}
	headerLength := int(packet[0]&0x0f) * 4
	totalLength := int(binary.BigEndian.Uint16(packet[2:4]))
	if headerLength < 20 || totalLength < headerLength+8 || totalLength > len(packet) || packet[9] != 17 {
		return netip.Addr{}, netip.Addr{}, 0, 0, nil, errors.New("service CUPS: invalid IPv4 or UDP length")
	}
	udpLength := int(binary.BigEndian.Uint16(packet[headerLength+4 : headerLength+6]))
	if udpLength < 8 || headerLength+udpLength > totalLength {
		return netip.Addr{}, netip.Addr{}, 0, 0, nil, errors.New("service CUPS: invalid UDP length")
	}
	source := netip.AddrFrom4([4]byte(packet[12:16]))
	destination := netip.AddrFrom4([4]byte(packet[16:20]))
	sourcePort := binary.BigEndian.Uint16(packet[headerLength : headerLength+2])
	destinationPort := binary.BigEndian.Uint16(packet[headerLength+2 : headerLength+4])
	payload := packet[headerLength+8 : headerLength+udpLength]
	return source, destination, sourcePort, destinationPort, payload, nil
}
