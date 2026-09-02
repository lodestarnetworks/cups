// Package epc provides a tiny MME/eNodeB/PGW harness for validating SGW Next.
// It is a test peer, not an EPC implementation.
package epc

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	gtptransport "github.com/lodestarnetworks/cups/internal/gtpv2/transport"
	"github.com/lodestarnetworks/cups/pkg/gtpu"
	"github.com/lodestarnetworks/cups/pkg/gtpv2"
)

type Config struct {
	MMEControl             netip.AddrPort
	SGWS11                 netip.AddrPort
	PGWControl             netip.AddrPort
	ENBUser                netip.AddrPort
	PGWUser                netip.AddrPort
	IMSI                   string
	APN                    string
	EBI                    uint8
	AdditionalAPN          string
	AdditionalEBI          uint8
	Timeout                time.Duration
	Transport              gtptransport.Config
	LatencySamples         int
	ThroughputDuration     time.Duration
	PayloadSize            int
	TargetPacketsPerSecond int
	SocketBufferBytes      int
	ExpectBufferedIdle     bool
}

type Result struct {
	MeasurementScope     string           `json:"measurementScope"`
	Subscriber           string           `json:"subscriber"`
	APN                  string           `json:"apn"`
	EBI                  uint8            `json:"ebi"`
	SGWS11TEID           uint32           `json:"sgwS11Teid"`
	SGWAccessTEID        uint32           `json:"sgwAccessTeid"`
	SGWCoreTEID          uint32           `json:"sgwCoreTeid"`
	UplinkBytes          int              `json:"uplinkBytes"`
	DownlinkBytes        int              `json:"downlinkBytes"`
	IdleDropVerified     bool             `json:"idleDropVerified"`
	DDNVerified          bool             `json:"ddnVerified"`
	BufferedIdleVerified bool             `json:"bufferedIdleVerified"`
	AdditionalPDN        bool             `json:"additionalPdnVerified"`
	AdditionalAPN        string           `json:"additionalApn,omitempty"`
	AdditionalEBI        uint8            `json:"additionalEbi,omitempty"`
	ControlLatency       ControlLatency   `json:"controlPlaneLatency"`
	UplinkLatency        LatencyResult    `json:"uplinkLatency"`
	DownlinkLatency      LatencyResult    `json:"downlinkLatency"`
	UplinkThroughput     ThroughputResult `json:"uplinkThroughput"`
	DownlinkThroughput   ThroughputResult `json:"downlinkThroughput"`
	ElapsedMilliseconds  float64          `json:"elapsedMilliseconds"`
}

type ControlLatency struct {
	CreateSessionMilliseconds           float64 `json:"createSessionMilliseconds"`
	ModifyBearerMilliseconds            float64 `json:"modifyBearerMilliseconds"`
	AdditionalCreateSessionMilliseconds float64 `json:"additionalCreateSessionMilliseconds,omitempty"`
	AdditionalModifyBearerMilliseconds  float64 `json:"additionalModifyBearerMilliseconds,omitempty"`
	ReleaseAccessMilliseconds           float64 `json:"releaseAccessMilliseconds"`
	ResumeBearerMilliseconds            float64 `json:"resumeBearerMilliseconds"`
	AdditionalResumeMilliseconds        float64 `json:"additionalResumeMilliseconds,omitempty"`
	AdditionalDeleteSessionMilliseconds float64 `json:"additionalDeleteSessionMilliseconds,omitempty"`
	DeleteSessionMilliseconds           float64 `json:"deleteSessionMilliseconds"`
}

type LatencyResult struct {
	Samples             int     `json:"samples"`
	MinimumMilliseconds float64 `json:"minimumMilliseconds"`
	AverageMilliseconds float64 `json:"averageMilliseconds"`
	P50Milliseconds     float64 `json:"p50Milliseconds"`
	P95Milliseconds     float64 `json:"p95Milliseconds"`
	P99Milliseconds     float64 `json:"p99Milliseconds"`
	MaximumMilliseconds float64 `json:"maximumMilliseconds"`
}

type ThroughputResult struct {
	DurationSeconds              float64 `json:"durationSeconds"`
	PayloadBytes                 int     `json:"payloadBytes"`
	TargetPacketsPerSecond       int     `json:"targetPacketsPerSecond"`
	SentPackets                  uint64  `json:"sentPackets"`
	ReceivedDatagrams            uint64  `json:"receivedDatagrams"`
	ReceivedPackets              uint64  `json:"receivedPackets"`
	DuplicatePackets             uint64  `json:"duplicatePackets"`
	OutOfOrderPackets            uint64  `json:"outOfOrderPackets"`
	SequenceTooOldPackets        uint64  `json:"sequenceTooOldPackets"`
	HighestSequence              uint64  `json:"highestSequence"`
	ReceiverSocketDroppedPackets uint64  `json:"receiverSocketDroppedPackets"`
	LostPackets                  uint64  `json:"lostPackets"`
	LossPercent                  float64 `json:"lossPercent"`
	PacketsPerSecond             float64 `json:"packetsPerSecond"`
	TargetMbps                   float64 `json:"targetMbps"`
	Mbps                         float64 `json:"mbps"`
}

type pgwPeer struct {
	mu              sync.Mutex
	controlIP       netip.Addr
	userIP          netip.Addr
	controlTEID     uint32
	userTEID        uint32
	sgwControlByEBI map[uint8]gtpv2.FTEID
	sgwUserByEBI    map[uint8]gtpv2.FTEID
	deletedByEBI    map[uint8]bool
}

type mmePeer struct {
	mu             sync.Mutex
	sgwControlTEID uint32
	enodebIP       netip.Addr
	dedicated      map[uint8]uint32
	ddn            chan uint8
}

func Run(ctx context.Context, config Config) (Result, error) {
	started := time.Now()
	controlLatency := ControlLatency{}
	if config.LatencySamples == 0 {
		config.LatencySamples = 100
	}
	if config.ThroughputDuration == 0 {
		config.ThroughputDuration = time.Second
	}
	if config.PayloadSize == 0 {
		config.PayloadSize = 1200
	}
	if config.SocketBufferBytes == 0 {
		config.SocketBufferBytes = 16 << 20
	}
	if err := validate(config); err != nil {
		return Result{}, err
	}
	peer := &pgwPeer{
		controlIP: config.PGWControl.Addr(), userIP: config.PGWUser.Addr(),
		controlTEID: 0x7f00_0001, userTEID: 0x7f00_1001,
	}
	pgw, err := gtptransport.Listen(config.PGWControl, peer.handle, config.Transport)
	if err != nil {
		return Result{}, err
	}
	defer pgw.Close()
	mmeHandler := &mmePeer{
		enodebIP:  config.ENBUser.Addr(),
		dedicated: make(map[uint8]uint32),
		ddn:       make(chan uint8, 4),
	}
	mme, err := gtptransport.Listen(config.MMEControl, mmeHandler.handle, config.Transport)
	if err != nil {
		return Result{}, err
	}
	defer mme.Close()
	enodeb, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(config.ENBUser))
	if err != nil {
		return Result{}, fmt.Errorf("listen lab eNodeB user plane: %w", err)
	}
	defer enodeb.Close()
	if err := configureUDPSocket(enodeb, config.SocketBufferBytes); err != nil {
		return Result{}, fmt.Errorf("configure lab eNodeB user plane: %w", err)
	}
	pgwUser, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(config.PGWUser))
	if err != nil {
		return Result{}, fmt.Errorf("listen lab PGW user plane: %w", err)
	}
	defer pgwUser.Close()
	if err := configureUDPSocket(pgwUser, config.SocketBufferBytes); err != nil {
		return Result{}, fmt.Errorf("configure lab PGW user plane: %w", err)
	}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	serveErrors := make(chan error, 2)
	go func() { serveErrors <- pgw.Serve(child) }()
	go func() { serveErrors <- mme.Serve(child) }()

	mmeTEID := uint32(0x1f00_0001)
	enodebTEID := uint32(0x2f00_0001)
	create, err := createRequest(config, mmeTEID)
	if err != nil {
		return Result{}, err
	}
	procedureStarted := time.Now()
	response, err := do(ctx, config.Timeout, mme, config.SGWS11, create)
	controlLatency.CreateSessionMilliseconds = milliseconds(time.Since(procedureStarted))
	if err != nil {
		return Result{}, fmt.Errorf("lab Create Session: %w", err)
	}
	if err := accepted(response); err != nil {
		return Result{}, fmt.Errorf("lab Create Session: %w", err)
	}
	sgwControl, err := findFTEID(response.IEs, 0)
	if err != nil || sgwControl.InterfaceType != gtpv2.InterfaceS11SGWGTPC {
		return Result{}, errors.New("lab Create Session: invalid SGW S11 F-TEID")
	}
	mmeHandler.setSGWControlTEID(sgwControl.TEID)
	createBearer, err := bearerChildren(response)
	if err != nil {
		return Result{}, err
	}
	sgwAccess, err := findFTEID(createBearer, 0)
	if err != nil || sgwAccess.InterfaceType != gtpv2.InterfaceS1USGWGTPU {
		return Result{}, errors.New("lab Create Session: invalid SGW S1-U F-TEID")
	}

	modify, err := modifyRequest(config, sgwControl.TEID, enodebTEID)
	if err != nil {
		return Result{}, err
	}
	procedureStarted = time.Now()
	response, err = do(ctx, config.Timeout, mme, config.SGWS11, modify)
	controlLatency.ModifyBearerMilliseconds = milliseconds(time.Since(procedureStarted))
	if err != nil {
		return Result{}, fmt.Errorf("lab Modify Bearer: %w", err)
	}
	if err := accepted(response); err != nil {
		return Result{}, fmt.Errorf("lab Modify Bearer: %w", err)
	}
	sgwCore, err := peer.userTunnel(config.EBI)
	if err != nil {
		return Result{}, err
	}

	var additionalAccess, additionalCore gtpv2.FTEID
	var additionalModify gtpv2.Message
	additionalPDNVerified := false
	additionalENodeBTEID := enodebTEID + 1
	if config.AdditionalAPN != "" {
		additionalCreate, buildErr := createPDNRequest(
			config, mmeTEID, sgwControl.TEID, config.AdditionalAPN, config.AdditionalEBI, 5,
		)
		if buildErr != nil {
			return Result{}, buildErr
		}
		procedureStarted = time.Now()
		response, err = do(ctx, config.Timeout, mme, config.SGWS11, additionalCreate)
		controlLatency.AdditionalCreateSessionMilliseconds = milliseconds(time.Since(procedureStarted))
		if err != nil {
			return Result{}, fmt.Errorf("lab additional-PDN Create Session: %w", err)
		}
		if err := accepted(response); err != nil {
			return Result{}, fmt.Errorf("lab additional-PDN Create Session: %w", err)
		}
		additionalControl, findErr := findFTEID(response.IEs, 0)
		if findErr != nil || additionalControl != sgwControl {
			return Result{}, errors.New("lab additional-PDN Create Session did not reuse the SGW S11 F-TEID")
		}
		additionalBearer, bearerErr := bearerChildren(response)
		if bearerErr != nil {
			return Result{}, bearerErr
		}
		additionalAccess, findErr = findFTEID(additionalBearer, 0)
		if findErr != nil || additionalAccess.InterfaceType != gtpv2.InterfaceS1USGWGTPU || additionalAccess.TEID == sgwAccess.TEID {
			return Result{}, errors.New("lab additional-PDN Create Session returned an invalid or reused S1-U F-TEID")
		}
		additionalModify, buildErr = modifyPDNRequest(config, sgwControl.TEID, additionalENodeBTEID, config.AdditionalEBI)
		if buildErr != nil {
			return Result{}, buildErr
		}
		procedureStarted = time.Now()
		response, err = do(ctx, config.Timeout, mme, config.SGWS11, additionalModify)
		controlLatency.AdditionalModifyBearerMilliseconds = milliseconds(time.Since(procedureStarted))
		if err != nil {
			return Result{}, fmt.Errorf("lab additional-PDN Modify Bearer: %w", err)
		}
		if err := accepted(response); err != nil {
			return Result{}, fmt.Errorf("lab additional-PDN Modify Bearer: %w", err)
		}
		additionalCore, err = peer.userTunnel(config.AdditionalEBI)
		if err != nil || additionalCore.TEID == sgwCore.TEID {
			return Result{}, errors.New("lab additional-PDN Modify Bearer used an invalid or reused S5-U F-TEID")
		}
	}

	uplinkPayload := []byte{0x45, 0x00, 0x00, 0x14, 0x53, 0x47, 0x57, 0x55}
	if err := sendGPDU(enodeb, netip.AddrPortFrom(sgwAccess.IPv4, 2152), sgwAccess.TEID, uplinkPayload); err != nil {
		return Result{}, err
	}
	if err := receiveGPDU(pgwUser, peer.userTEIDForEBI(config.EBI), uplinkPayload, config.Timeout); err != nil {
		return Result{}, fmt.Errorf("lab uplink: %w", err)
	}
	downlinkPayload := []byte{0x45, 0x00, 0x00, 0x14, 0x53, 0x47, 0x57, 0x44}
	if err := sendGPDU(pgwUser, netip.AddrPortFrom(sgwCore.IPv4, 2152), sgwCore.TEID, downlinkPayload); err != nil {
		return Result{}, err
	}
	if err := receiveGPDU(enodeb, enodebTEID, downlinkPayload, config.Timeout); err != nil {
		return Result{}, fmt.Errorf("lab downlink: %w", err)
	}
	if config.AdditionalAPN != "" {
		additionalUplink := []byte{0x45, 0x00, 0x00, 0x14, 0x49, 0x4d, 0x53, 0x55}
		if err := sendGPDU(enodeb, netip.AddrPortFrom(additionalAccess.IPv4, 2152), additionalAccess.TEID, additionalUplink); err != nil {
			return Result{}, err
		}
		if err := receiveGPDU(pgwUser, peer.userTEIDForEBI(config.AdditionalEBI), additionalUplink, config.Timeout); err != nil {
			return Result{}, fmt.Errorf("lab additional-PDN uplink: %w", err)
		}
		additionalDownlink := []byte{0x45, 0x00, 0x00, 0x14, 0x49, 0x4d, 0x53, 0x44}
		if err := sendGPDU(pgwUser, netip.AddrPortFrom(additionalCore.IPv4, 2152), additionalCore.TEID, additionalDownlink); err != nil {
			return Result{}, err
		}
		if err := receiveGPDU(enodeb, additionalENodeBTEID, additionalDownlink, config.Timeout); err != nil {
			return Result{}, fmt.Errorf("lab additional-PDN downlink: %w", err)
		}
	}

	release := gtpv2.Message{Header: gtpv2.Header{
		Version: gtpv2.Version, HasTEID: true,
		MessageType: gtpv2.MessageReleaseAccessBearersRequest, TEID: sgwControl.TEID,
	}}
	procedureStarted = time.Now()
	response, err = do(ctx, config.Timeout, mme, config.SGWS11, release)
	controlLatency.ReleaseAccessMilliseconds = milliseconds(time.Since(procedureStarted))
	if err != nil {
		return Result{}, fmt.Errorf("lab Release Access Bearers: %w", err)
	}
	if err := accepted(response); err != nil {
		return Result{}, fmt.Errorf("lab Release Access Bearers: %w", err)
	}
	if err := sendGPDU(pgwUser, netip.AddrPortFrom(sgwCore.IPv4, 2152), sgwCore.TEID, downlinkPayload); err != nil {
		return Result{}, err
	}
	if err := expectNoPacket(enodeb, min(config.Timeout/4, 250*time.Millisecond)); err != nil {
		return Result{}, fmt.Errorf("lab idle gate: %w", err)
	}
	if err := mmeHandler.waitForDDN(config.EBI, config.Timeout); err != nil {
		return Result{}, fmt.Errorf("lab idle paging: %w", err)
	}
	var additionalIdlePayload []byte
	if config.AdditionalAPN != "" {
		additionalIdlePayload = []byte{0x45, 0x00, 0x00, 0x14, 0x49, 0x44, 0x4c, 0x45}
		if err := sendGPDU(pgwUser, netip.AddrPortFrom(additionalCore.IPv4, 2152), additionalCore.TEID, additionalIdlePayload); err != nil {
			return Result{}, err
		}
		if err := expectNoPacket(enodeb, min(config.Timeout/4, 250*time.Millisecond)); err != nil {
			return Result{}, fmt.Errorf("lab additional-PDN idle gate: %w", err)
		}
		if err := mmeHandler.waitForDDN(config.AdditionalEBI, config.Timeout); err != nil {
			return Result{}, fmt.Errorf("lab additional-PDN idle paging: %w", err)
		}
	}

	procedureStarted = time.Now()
	response, err = do(ctx, config.Timeout, mme, config.SGWS11, modify)
	controlLatency.ResumeBearerMilliseconds = milliseconds(time.Since(procedureStarted))
	if err != nil {
		return Result{}, fmt.Errorf("lab resume Modify Bearer: %w", err)
	}
	if err := accepted(response); err != nil {
		return Result{}, fmt.Errorf("lab resume Modify Bearer: %w", err)
	}
	bufferedIdleVerified := false
	if config.ExpectBufferedIdle {
		if err := receiveGPDU(enodeb, enodebTEID, downlinkPayload, config.Timeout); err != nil {
			return Result{}, fmt.Errorf("lab buffered idle downlink after resume: %w", err)
		}
		bufferedIdleVerified = true
	}
	if config.AdditionalAPN != "" {
		procedureStarted = time.Now()
		response, err = do(ctx, config.Timeout, mme, config.SGWS11, additionalModify)
		controlLatency.AdditionalResumeMilliseconds = milliseconds(time.Since(procedureStarted))
		if err != nil {
			return Result{}, fmt.Errorf("lab additional-PDN resume Modify Bearer: %w", err)
		}
		if err := accepted(response); err != nil {
			return Result{}, fmt.Errorf("lab additional-PDN resume Modify Bearer: %w", err)
		}
		if config.ExpectBufferedIdle {
			if err := receiveGPDU(enodeb, additionalENodeBTEID, additionalIdlePayload, config.Timeout); err != nil {
				return Result{}, fmt.Errorf("lab additional-PDN buffered idle downlink after resume: %w", err)
			}
		}
		additionalResumePayload := []byte{0x45, 0x00, 0x00, 0x14, 0x52, 0x45, 0x53, 0x55}
		if err := sendGPDU(pgwUser, netip.AddrPortFrom(additionalCore.IPv4, 2152), additionalCore.TEID, additionalResumePayload); err != nil {
			return Result{}, err
		}
		if err := receiveGPDU(enodeb, additionalENodeBTEID, additionalResumePayload, config.Timeout); err != nil {
			return Result{}, fmt.Errorf("lab additional-PDN resume traffic: %w", err)
		}
	}

	uplinkLatency, err := measureLatency(
		ctx, enodeb, pgwUser, netip.AddrPortFrom(sgwAccess.IPv4, 2152),
		sgwAccess.TEID, peer.userTEIDForEBI(config.EBI), config.LatencySamples, config.PayloadSize, config.Timeout,
	)
	if err != nil {
		return Result{}, fmt.Errorf("lab uplink latency: %w", err)
	}
	downlinkLatency, err := measureLatency(
		ctx, pgwUser, enodeb, netip.AddrPortFrom(sgwCore.IPv4, 2152),
		sgwCore.TEID, enodebTEID, config.LatencySamples, config.PayloadSize, config.Timeout,
	)
	if err != nil {
		return Result{}, fmt.Errorf("lab downlink latency: %w", err)
	}
	uplinkThroughput, err := measureThroughput(
		ctx, enodeb, pgwUser, netip.AddrPortFrom(sgwAccess.IPv4, 2152),
		sgwAccess.TEID, peer.userTEIDForEBI(config.EBI), config.ThroughputDuration, config.PayloadSize,
		config.TargetPacketsPerSecond,
	)
	if err != nil {
		return Result{}, fmt.Errorf("lab uplink throughput: %w", err)
	}
	downlinkThroughput, err := measureThroughput(
		ctx, pgwUser, enodeb, netip.AddrPortFrom(sgwCore.IPv4, 2152),
		sgwCore.TEID, enodebTEID, config.ThroughputDuration, config.PayloadSize,
		config.TargetPacketsPerSecond,
	)
	if err != nil {
		return Result{}, fmt.Errorf("lab downlink throughput: %w", err)
	}
	if config.AdditionalAPN != "" {
		additionalEBIIE, _ := gtpv2.NewEBIIE(config.AdditionalEBI, 0)
		additionalDelete := gtpv2.Message{
			Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageDeleteSessionRequest, TEID: sgwControl.TEID},
			IEs:    []gtpv2.IE{additionalEBIIE},
		}
		procedureStarted = time.Now()
		response, err = do(ctx, config.Timeout, mme, config.SGWS11, additionalDelete)
		controlLatency.AdditionalDeleteSessionMilliseconds = milliseconds(time.Since(procedureStarted))
		if err != nil {
			return Result{}, fmt.Errorf("lab additional-PDN Delete Session: %w", err)
		}
		if err := accepted(response); err != nil {
			return Result{}, fmt.Errorf("lab additional-PDN Delete Session: %w", err)
		}
		if !peer.wasDeleted(config.AdditionalEBI) {
			return Result{}, errors.New("lab PGW did not receive the additional-PDN Delete Session")
		}
		additionalPDNVerified = true
	}
	ebiIE, _ := gtpv2.NewEBIIE(config.EBI, 0)
	deleteRequest := gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageDeleteSessionRequest, TEID: sgwControl.TEID},
		IEs:    []gtpv2.IE{ebiIE},
	}
	procedureStarted = time.Now()
	response, err = do(ctx, config.Timeout, mme, config.SGWS11, deleteRequest)
	controlLatency.DeleteSessionMilliseconds = milliseconds(time.Since(procedureStarted))
	if err != nil {
		return Result{}, fmt.Errorf("lab Delete Session: %w", err)
	}
	if err := accepted(response); err != nil {
		return Result{}, fmt.Errorf("lab Delete Session: %w", err)
	}

	return Result{
		MeasurementScope: "local synthetic EPC; inner-payload goodput",
		Subscriber:       maskIMSI(config.IMSI), APN: config.APN, EBI: config.EBI,
		SGWS11TEID: sgwControl.TEID, SGWAccessTEID: sgwAccess.TEID, SGWCoreTEID: sgwCore.TEID,
		UplinkBytes: len(uplinkPayload), DownlinkBytes: len(downlinkPayload),
		IdleDropVerified: true, DDNVerified: true, BufferedIdleVerified: bufferedIdleVerified,
		AdditionalPDN: additionalPDNVerified,
		AdditionalAPN: config.AdditionalAPN, AdditionalEBI: config.AdditionalEBI, ControlLatency: controlLatency,
		UplinkLatency: uplinkLatency, DownlinkLatency: downlinkLatency,
		UplinkThroughput: uplinkThroughput, DownlinkThroughput: downlinkThroughput,
		ElapsedMilliseconds: milliseconds(time.Since(started)),
	}, nil
}

func validate(config Config) error {
	for name, value := range map[string]netip.AddrPort{
		"MME control": config.MMEControl, "SGW S11": config.SGWS11,
		"PGW control": config.PGWControl, "eNodeB user": config.ENBUser, "PGW user": config.PGWUser,
	} {
		if !value.Addr().Is4() || value.Port() == 0 {
			return fmt.Errorf("lab EPC: %s requires an IPv4 address and port", name)
		}
	}
	if config.IMSI == "" || config.APN == "" || config.EBI < 5 || config.EBI > 15 || config.Timeout <= 0 {
		return errors.New("lab EPC: IMSI, APN, LTE EBI, and timeout are required")
	}
	if config.AdditionalAPN != "" && (config.AdditionalEBI < 5 || config.AdditionalEBI > 15 || config.AdditionalEBI == config.EBI) {
		return errors.New("lab EPC: additional PDN requires a distinct LTE EBI between 5 and 15")
	}
	if config.MMEControl.Port() != 2123 {
		return errors.New("lab EPC: MME control listener must use the standard UDP port 2123 for DDN")
	}
	if config.LatencySamples < 1 || config.LatencySamples > 100_000 {
		return errors.New("lab EPC: latency samples must be between 1 and 100000")
	}
	if config.ThroughputDuration < 100*time.Millisecond || config.ThroughputDuration > 10*time.Minute {
		return errors.New("lab EPC: throughput duration must be between 100ms and 10m")
	}
	if config.PayloadSize < 64 || config.PayloadSize > 65_000 {
		return errors.New("lab EPC: payload size must be between 64 and 65000 bytes")
	}
	if config.TargetPacketsPerSecond < 0 || config.TargetPacketsPerSecond > 1_000_000 {
		return errors.New("lab EPC: target packet rate must be zero (unlimited) or between 1 and 1000000")
	}
	if config.SocketBufferBytes < 64<<10 || config.SocketBufferBytes > 1<<30 {
		return errors.New("lab EPC: socket buffer must be between 65536 and 1073741824 bytes")
	}
	return nil
}

func configureUDPSocket(conn *net.UDPConn, bytes int) error {
	if err := conn.SetReadBuffer(bytes); err != nil {
		return err
	}
	return conn.SetWriteBuffer(bytes)
}

func createRequest(config Config, mmeTEID uint32) (gtpv2.Message, error) {
	return createPDNRequest(config, mmeTEID, 0, config.APN, config.EBI, 9)
}

func createPDNRequest(config Config, mmeTEID, sgwTEID uint32, apnName string, ebi, qci uint8) (gtpv2.Message, error) {
	imsi, err := gtpv2.NewIMSIIE(config.IMSI)
	if err != nil {
		return gtpv2.Message{}, err
	}
	apn, err := gtpv2.NewAPNIE(apnName)
	if err != nil {
		return gtpv2.Message{}, err
	}
	mme, err := gtpv2.NewFTEIDIE(0, gtpv2.FTEID{InterfaceType: gtpv2.InterfaceS11MMEGTPC, TEID: mmeTEID, IPv4: config.MMEControl.Addr()})
	if err != nil {
		return gtpv2.Message{}, err
	}
	ebiIE, _ := gtpv2.NewEBIIE(ebi, 0)
	qos, _ := gtpv2.NewBearerQoSIE(0, qci, 8)
	bearer, err := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, ebiIE, qos)
	if err != nil {
		return gtpv2.Message{}, err
	}
	return gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageCreateSessionRequest, TEID: sgwTEID},
		IEs:    []gtpv2.IE{imsi, apn, mme, bearer},
	}, nil
}

func modifyRequest(config Config, sgwTEID, enodebTEID uint32) (gtpv2.Message, error) {
	return modifyPDNRequest(config, sgwTEID, enodebTEID, config.EBI)
}

func modifyPDNRequest(config Config, sgwTEID, enodebTEID uint32, ebi uint8) (gtpv2.Message, error) {
	ebiIE, _ := gtpv2.NewEBIIE(ebi, 0)
	enodeb, err := gtpv2.NewFTEIDIE(0, gtpv2.FTEID{
		InterfaceType: gtpv2.InterfaceS1UENodeBGTPU, TEID: enodebTEID, IPv4: config.ENBUser.Addr(),
	})
	if err != nil {
		return gtpv2.Message{}, err
	}
	bearer, err := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, ebiIE, enodeb)
	if err != nil {
		return gtpv2.Message{}, err
	}
	return gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageModifyBearerRequest, TEID: sgwTEID},
		IEs:    []gtpv2.IE{bearer},
	}, nil
}

func (m *mmePeer) setSGWControlTEID(teid uint32) {
	m.mu.Lock()
	m.sgwControlTEID = teid
	m.mu.Unlock()
}

func (m *mmePeer) handle(_ context.Context, _ netip.AddrPort, request gtpv2.Message) (*gtpv2.Message, error) {
	m.mu.Lock()
	sgwTEID := m.sgwControlTEID
	m.mu.Unlock()
	if sgwTEID == 0 {
		return nil, errors.New("lab MME: SGW control TEID is unknown")
	}

	switch request.Header.MessageType {
	case gtpv2.MessageDownlinkDataNotification:
		ebiIE, ok := request.Find(gtpv2.IEEBI, 0)
		if !ok {
			return nil, errors.New("lab MME: DDN missing EBI")
		}
		ebi, err := ebiIE.EBI()
		if err != nil {
			return nil, err
		}
		select {
		case m.ddn <- ebi:
		default:
		}
		return &gtpv2.Message{
			Header: gtpv2.Header{
				Version: gtpv2.Version, HasTEID: true,
				MessageType: gtpv2.MessageDownlinkDataNotificationAck, TEID: sgwTEID,
			},
			IEs: []gtpv2.IE{gtpv2.NewCauseIE(gtpv2.CauseRequestAccepted, 0)},
		}, nil
	case gtpv2.MessageCreateBearerRequest:
		children, err := bearerChildren(request)
		if err != nil {
			return nil, err
		}
		ebiIE, ebiOK := gtpv2.FindIE(children, gtpv2.IEEBI, 0)
		sgwAccessIE, accessOK := gtpv2.FindIE(children, gtpv2.IEFTEID, 0)
		if !ebiOK || !accessOK {
			return nil, errors.New("lab MME: Create Bearer omitted EBI or SGW S1-U F-TEID")
		}
		ebi, err := ebiIE.EBI()
		if err != nil {
			return nil, err
		}
		sgwAccess, err := sgwAccessIE.FTEID()
		if err != nil || sgwAccess.InterfaceType != gtpv2.InterfaceS1USGWGTPU || sgwAccess.TEID == 0 || !sgwAccess.IPv4.Is4() {
			return nil, errors.New("lab MME: invalid SGW S1-U F-TEID")
		}
		m.mu.Lock()
		if !m.enodebIP.Is4() {
			m.mu.Unlock()
			return nil, errors.New("lab MME: eNodeB user-plane IPv4 address is unavailable")
		}
		enodebIP := m.enodebIP
		enodebTEID := uint32(0x7c00_0000) | uint32(ebi)
		if m.dedicated == nil {
			m.dedicated = make(map[uint8]uint32)
		}
		if _, exists := m.dedicated[ebi]; exists {
			m.mu.Unlock()
			return bearerMMEResponse(gtpv2.MessageCreateBearerResponse, sgwTEID, ebiIE, gtpv2.CauseNoResourcesAvailable, gtpv2.IE{})
		}
		m.dedicated[ebi] = enodebTEID
		m.mu.Unlock()
		enodeb, err := gtpv2.NewFTEIDIE(0, gtpv2.FTEID{
			InterfaceType: gtpv2.InterfaceS1UENodeBGTPU,
			TEID:          enodebTEID,
			IPv4:          enodebIP,
		})
		if err != nil {
			return nil, err
		}
		return bearerMMEResponse(gtpv2.MessageCreateBearerResponse, sgwTEID, ebiIE, gtpv2.CauseRequestAccepted, enodeb)
	case gtpv2.MessageUpdateBearerRequest:
		children, err := bearerChildren(request)
		if err != nil {
			return nil, err
		}
		ebiIE, ok := gtpv2.FindIE(children, gtpv2.IEEBI, 0)
		if !ok {
			return nil, errors.New("lab MME: Update Bearer omitted EBI")
		}
		ebi, err := ebiIE.EBI()
		if err != nil {
			return nil, err
		}
		m.mu.Lock()
		_, exists := m.dedicated[ebi]
		m.mu.Unlock()
		cause := uint8(gtpv2.CauseRequestAccepted)
		if !exists {
			cause = gtpv2.CauseContextNotFound
		}
		return bearerMMEResponse(gtpv2.MessageUpdateBearerResponse, sgwTEID, ebiIE, cause, gtpv2.IE{})
	case gtpv2.MessageDeleteBearerRequest:
		ebiIE, ok := request.Find(gtpv2.IEEBI, 1)
		if !ok {
			return nil, errors.New("lab MME: Delete Bearer omitted EBI")
		}
		ebi, err := ebiIE.EBI()
		if err != nil {
			return nil, err
		}
		m.mu.Lock()
		_, exists := m.dedicated[ebi]
		if exists {
			delete(m.dedicated, ebi)
		}
		m.mu.Unlock()
		cause := uint8(gtpv2.CauseRequestAccepted)
		if !exists {
			cause = gtpv2.CauseContextNotFound
		}
		return bearerMMEResponse(gtpv2.MessageDeleteBearerResponse, sgwTEID, ebiIE, cause, gtpv2.IE{})
	default:
		return nil, fmt.Errorf("lab MME: unsupported request %d", request.Header.MessageType)
	}
}

func bearerMMEResponse(messageType uint8, sgwTEID uint32, ebiIE gtpv2.IE, cause uint8, extra gtpv2.IE) (*gtpv2.Message, error) {
	children := []gtpv2.IE{ebiIE, gtpv2.NewCauseIE(cause, 0)}
	if extra.Type != 0 {
		children = append(children, extra)
	}
	bearer, err := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, children...)
	if err != nil {
		return nil, err
	}
	return &gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: messageType, TEID: sgwTEID},
		IEs:    []gtpv2.IE{gtpv2.NewCauseIE(cause, 0), bearer},
	}, nil
}

func (m *mmePeer) waitForDDN(expectedEBI uint8, timeout time.Duration) error {
	select {
	case ebi := <-m.ddn:
		if ebi != expectedEBI {
			return fmt.Errorf("DDN EBI %d, expected %d", ebi, expectedEBI)
		}
		return nil
	case <-time.After(timeout):
		return errors.New("timed out waiting for Downlink Data Notification")
	}
}

func (p *pgwPeer) handle(_ context.Context, _ netip.AddrPort, request gtpv2.Message) (*gtpv2.Message, error) {
	switch request.Header.MessageType {
	case gtpv2.MessageEchoRequest:
		return &gtpv2.Message{Header: gtpv2.Header{Version: gtpv2.Version, MessageType: gtpv2.MessageEchoResponse}, IEs: []gtpv2.IE{gtpv2.NewRecoveryIE(1)}}, nil
	case gtpv2.MessageCreateSessionRequest:
		sgwControl, err := findFTEID(request.IEs, 0)
		if err != nil {
			return nil, err
		}
		children, err := bearerChildren(request)
		if err != nil {
			return nil, err
		}
		sgwUser, err := findFTEID(children, 2)
		if err != nil || sgwUser.InterfaceType != gtpv2.InterfaceS5S8SGWGTPU {
			return nil, errors.New("lab PGW: missing or invalid SGW S5-U F-TEID in Create Session")
		}
		ebiIE, ok := gtpv2.FindIE(children, gtpv2.IEEBI, 0)
		if !ok {
			return nil, gtpv2.ErrMissingIE
		}
		ebi, err := ebiIE.EBI()
		if err != nil {
			return nil, err
		}
		control, _ := gtpv2.NewFTEIDIE(1, gtpv2.FTEID{InterfaceType: gtpv2.InterfaceS5S8PGWGTPC, TEID: p.controlTEIDForEBI(ebi), IPv4: p.controlIP})
		user, _ := gtpv2.NewFTEIDIE(2, gtpv2.FTEID{InterfaceType: gtpv2.InterfaceS5S8PGWGTPU, TEID: p.userTEIDForEBI(ebi), IPv4: p.userIP})
		bearer, _ := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, ebiIE, gtpv2.NewCauseIE(gtpv2.CauseRequestAccepted, 0), user)
		p.mu.Lock()
		p.ensureMapsLocked()
		p.sgwControlByEBI[ebi] = sgwControl
		p.sgwUserByEBI[ebi] = sgwUser
		p.mu.Unlock()
		return &gtpv2.Message{
			Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageCreateSessionResponse, TEID: sgwControl.TEID},
			IEs:    []gtpv2.IE{gtpv2.NewCauseIE(gtpv2.CauseRequestAccepted, 0), control, bearer},
		}, nil
	case gtpv2.MessageModifyBearerRequest:
		children, err := bearerChildren(request)
		if err != nil {
			return nil, err
		}
		sgwUser, err := findFTEID(children, 1)
		if err != nil {
			return nil, err
		}
		ebiIE, ok := gtpv2.FindIE(children, gtpv2.IEEBI, 0)
		if !ok {
			return nil, gtpv2.ErrMissingIE
		}
		ebi, err := ebiIE.EBI()
		if err != nil {
			return nil, err
		}
		bearer, _ := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, ebiIE, gtpv2.NewCauseIE(gtpv2.CauseRequestAccepted, 0))
		p.mu.Lock()
		p.ensureMapsLocked()
		p.sgwUserByEBI[ebi] = sgwUser
		sgwControl := p.sgwControlByEBI[ebi]
		p.mu.Unlock()
		if request.Header.TEID != p.controlTEIDForEBI(ebi) || sgwControl.TEID == 0 {
			return nil, errors.New("lab PGW: Modify Bearer addressed the wrong PDN control tunnel")
		}
		return &gtpv2.Message{
			Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageModifyBearerResponse, TEID: sgwControl.TEID},
			IEs:    []gtpv2.IE{gtpv2.NewCauseIE(gtpv2.CauseRequestAccepted, 0), bearer},
		}, nil
	case gtpv2.MessageDeleteSessionRequest:
		ebiIE, ok := request.Find(gtpv2.IEEBI, 0)
		if !ok {
			return nil, errors.New("lab PGW: Delete Session missing linked EBI")
		}
		ebi, err := ebiIE.EBI()
		if err != nil {
			return nil, err
		}
		p.mu.Lock()
		p.ensureMapsLocked()
		sgwControl := p.sgwControlByEBI[ebi]
		p.deletedByEBI[ebi] = true
		p.mu.Unlock()
		if request.Header.TEID != p.controlTEIDForEBI(ebi) || sgwControl.TEID == 0 {
			return nil, errors.New("lab PGW: Delete Session addressed the wrong PDN control tunnel")
		}
		return &gtpv2.Message{
			Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageDeleteSessionResponse, TEID: sgwControl.TEID},
			IEs:    []gtpv2.IE{gtpv2.NewCauseIE(gtpv2.CauseRequestAccepted, 0)},
		}, nil
	default:
		return nil, errors.New("lab PGW: unsupported request")
	}
}

func (p *pgwPeer) ensureMapsLocked() {
	if p.sgwControlByEBI == nil {
		p.sgwControlByEBI = make(map[uint8]gtpv2.FTEID)
		p.sgwUserByEBI = make(map[uint8]gtpv2.FTEID)
		p.deletedByEBI = make(map[uint8]bool)
	}
}

func (p *pgwPeer) controlTEIDForEBI(ebi uint8) uint32 {
	return p.controlTEID + uint32(ebi-5)
}

func (p *pgwPeer) userTEIDForEBI(ebi uint8) uint32 {
	return p.userTEID + uint32(ebi-5)
}

func (p *pgwPeer) userTunnel(ebi uint8) (gtpv2.FTEID, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	tunnel := p.sgwUserByEBI[ebi]
	if tunnel.TEID == 0 {
		return gtpv2.FTEID{}, errors.New("lab PGW did not receive the SGW S5-U F-TEID")
	}
	return tunnel, nil
}

func (p *pgwPeer) wasDeleted(ebi uint8) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.deletedByEBI[ebi]
}

func do(ctx context.Context, timeout time.Duration, endpoint *gtptransport.Endpoint, peer netip.AddrPort, request gtpv2.Message) (gtpv2.Message, error) {
	opCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return endpoint.Do(opCtx, peer, request)
}

func accepted(message gtpv2.Message) error {
	ie, ok := message.Find(gtpv2.IECause, 0)
	if !ok {
		return gtpv2.ErrMissingIE
	}
	cause, err := ie.Cause()
	if err != nil {
		return err
	}
	if cause.Value != gtpv2.CauseRequestAccepted {
		return fmt.Errorf("rejected with GTP cause %d", cause.Value)
	}
	return nil
}

func bearerChildren(message gtpv2.Message) ([]gtpv2.IE, error) {
	ie, ok := message.Find(gtpv2.IEBearerContext, 0)
	if !ok {
		return nil, gtpv2.ErrMissingIE
	}
	return ie.Children()
}

func findFTEID(ies []gtpv2.IE, instance uint8) (gtpv2.FTEID, error) {
	ie, ok := gtpv2.FindIE(ies, gtpv2.IEFTEID, instance)
	if !ok {
		return gtpv2.FTEID{}, gtpv2.ErrMissingIE
	}
	return ie.FTEID()
}

func sendGPDU(conn *net.UDPConn, peer netip.AddrPort, teid uint32, payload []byte) error {
	wire, err := gtpu.Marshal(gtpu.Header{Version: gtpu.Version, ProtocolType: true, MessageType: gtpu.MessageGPDU, TEID: teid}, payload)
	if err != nil {
		return err
	}
	_, err = conn.WriteToUDPAddrPort(wire, peer)
	return err
}

func receiveGPDU(conn *net.UDPConn, expectedTEID uint32, expectedPayload []byte, timeout time.Duration) error {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buffer := make([]byte, 65_535)
	n, _, err := conn.ReadFromUDPAddrPort(buffer)
	if err != nil {
		return err
	}
	header, payload, err := gtpu.Parse(buffer[:n])
	if err != nil {
		return err
	}
	if header.TEID != expectedTEID || string(payload) != string(expectedPayload) {
		return fmt.Errorf("unexpected GTP-U packet TEID=%#x payload=%x", header.TEID, payload)
	}
	return nil
}

func expectNoPacket(conn *net.UDPConn, timeout time.Duration) error {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buffer := make([]byte, 1500)
	_, _, err := conn.ReadFromUDPAddrPort(buffer)
	var netError net.Error
	if !errors.As(err, &netError) || !netError.Timeout() {
		return fmt.Errorf("expected idle downlink drop, read error=%v", err)
	}
	return nil
}

func measureLatency(ctx context.Context, sender, receiver *net.UDPConn, destination netip.AddrPort, incomingTEID, outgoingTEID uint32, samples, payloadSize int, timeout time.Duration) (LatencyResult, error) {
	durations := make([]time.Duration, 0, samples)
	buffer := make([]byte, 65_535)
	for sequence := 0; sequence < samples; sequence++ {
		select {
		case <-ctx.Done():
			return LatencyResult{}, ctx.Err()
		default:
		}
		payload := benchmarkPayload(payloadSize, uint64(sequence))
		wire, err := gtpu.Marshal(gtpu.Header{Version: gtpu.Version, ProtocolType: true, MessageType: gtpu.MessageGPDU, TEID: incomingTEID}, payload)
		if err != nil {
			return LatencyResult{}, err
		}
		started := time.Now()
		if _, err := sender.WriteToUDPAddrPort(wire, destination); err != nil {
			return LatencyResult{}, err
		}
		_ = receiver.SetReadDeadline(time.Now().Add(timeout))
		n, _, err := receiver.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return LatencyResult{}, err
		}
		header, received, err := gtpu.Parse(buffer[:n])
		if err != nil {
			return LatencyResult{}, err
		}
		if header.TEID != outgoingTEID || string(received) != string(payload) {
			return LatencyResult{}, errors.New("latency sample was corrupted or used the wrong TEID")
		}
		durations = append(durations, time.Since(started))
	}
	return latencySummary(durations), nil
}

func measureThroughput(ctx context.Context, sender, receiver *net.UDPConn, destination netip.AddrPort, incomingTEID, outgoingTEID uint32, duration time.Duration, payloadSize, targetPPS int) (ThroughputResult, error) {
	type receiveResult struct {
		packets uint64
		err     error
	}
	sendingDone := make(chan struct{})
	received := make(chan receiveResult, 1)
	go func() {
		buffer := make([]byte, 65_535)
		var packets uint64
		for {
			_ = receiver.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, _, err := receiver.ReadFromUDPAddrPort(buffer)
			if err != nil {
				var netError net.Error
				if errors.As(err, &netError) && netError.Timeout() {
					select {
					case <-sendingDone:
						received <- receiveResult{packets: packets}
						return
					default:
						continue
					}
				}
				received <- receiveResult{packets: packets, err: err}
				return
			}
			header, payload, err := gtpu.Parse(buffer[:n])
			if err != nil || header.MessageType != gtpu.MessageGPDU || header.TEID != outgoingTEID || len(payload) != payloadSize {
				received <- receiveResult{packets: packets, err: errors.New("invalid packet during throughput run")}
				return
			}
			packets++
		}
	}()

	started := time.Now()
	end := started.Add(duration)
	var sent uint64
	sendOne := func() error {
		payload := benchmarkPayload(payloadSize, sent)
		wire, err := gtpu.Marshal(gtpu.Header{Version: gtpu.Version, ProtocolType: true, MessageType: gtpu.MessageGPDU, TEID: incomingTEID}, payload)
		if err != nil {
			return err
		}
		if _, err := sender.WriteToUDPAddrPort(wire, destination); err != nil {
			return err
		}
		sent++
		return nil
	}
	var sendErr error
	if targetPPS == 0 {
		for time.Now().Before(end) {
			select {
			case <-ctx.Done():
				sendErr = ctx.Err()
			default:
				sendErr = sendOne()
			}
			if sendErr != nil {
				break
			}
		}
	} else {
		ticker := time.NewTicker(time.Millisecond)
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
				for index := 0; index < packets; index++ {
					if sendErr = sendOne(); sendErr != nil {
						break paceLoop
					}
				}
			}
		}
		ticker.Stop()
	}
	elapsed := time.Since(started)
	close(sendingDone)
	var result receiveResult
	select {
	case result = <-received:
	case <-ctx.Done():
		return ThroughputResult{}, ctx.Err()
	case <-time.After(2 * time.Second):
		return ThroughputResult{}, errors.New("timed out draining throughput receiver")
	}
	if result.err != nil {
		return ThroughputResult{}, result.err
	}
	if sendErr != nil {
		return ThroughputResult{}, sendErr
	}
	lost := uint64(0)
	if result.packets < sent {
		lost = sent - result.packets
	}
	seconds := elapsed.Seconds()
	lossPercent := float64(0)
	if sent > 0 {
		lossPercent = float64(lost) / float64(sent) * 100
	}
	return ThroughputResult{
		DurationSeconds: seconds, PayloadBytes: payloadSize, TargetPacketsPerSecond: targetPPS,
		SentPackets: sent, ReceivedPackets: result.packets, LostPackets: lost,
		LossPercent: lossPercent, PacketsPerSecond: float64(result.packets) / seconds,
		TargetMbps: float64(targetPPS*payloadSize*8) / 1_000_000,
		Mbps:       float64(result.packets*uint64(payloadSize)*8) / seconds / 1_000_000,
	}, nil
}

func benchmarkPayload(size int, sequence uint64) []byte {
	payload := make([]byte, size)
	payload[0] = 0x45
	binary.BigEndian.PutUint64(payload[8:16], sequence)
	for index := 16; index < len(payload); index++ {
		payload[index] = byte(index + int(sequence))
	}
	return payload
}

func latencySummary(values []time.Duration) LatencyResult {
	sorted := append([]time.Duration(nil), values...)
	sort.Slice(sorted, func(left, right int) bool { return sorted[left] < sorted[right] })
	var total time.Duration
	for _, value := range sorted {
		total += value
	}
	return LatencyResult{
		Samples: len(sorted), MinimumMilliseconds: milliseconds(sorted[0]),
		AverageMilliseconds: milliseconds(total) / float64(len(sorted)),
		P50Milliseconds:     milliseconds(percentile(sorted, 0.50)),
		P95Milliseconds:     milliseconds(percentile(sorted, 0.95)),
		P99Milliseconds:     milliseconds(percentile(sorted, 0.99)),
		MaximumMilliseconds: milliseconds(sorted[len(sorted)-1]),
	}
}

func percentile(sorted []time.Duration, quantile float64) time.Duration {
	index := int(float64(len(sorted))*quantile+0.999999) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index]
}

func milliseconds(value time.Duration) float64 {
	return float64(value.Nanoseconds()) / 1_000_000
}

func maskIMSI(imsi string) string {
	if len(imsi) <= 4 {
		return "••••"
	}
	return "••••" + imsi[len(imsi)-4:]
}
