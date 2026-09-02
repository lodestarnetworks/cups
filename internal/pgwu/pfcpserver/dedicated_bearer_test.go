package pfcpserver

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/lodestarnetworks/cups/internal/pgwu/rules"
	"github.com/lodestarnetworks/cups/pkg/pfcp"
)

func TestDecodeSessionBuildsDefaultAndDedicatedBearerFromStandardSDF(t *testing.T) {
	const enterpriseID uint16 = 65000
	server := &Server{config: Config{
		UserIP: netip.MustParseAddr("10.200.0.20"), DedicatedUserIP: netip.MustParseAddr("10.200.0.21"), EnterpriseID: enterpriseID,
	}}
	ue := netip.MustParseAddr("10.90.0.2")
	local := rules.Tunnel{TEID: 100, IP: netip.MustParseAddr("10.200.0.20")}
	remote := rules.Tunnel{TEID: 200, IP: netip.MustParseAddr("10.200.0.10")}
	dedicatedLocal := rules.Tunnel{TEID: 101, IP: server.config.DedicatedUserIP}
	dedicatedRemote := rules.Tunnel{TEID: 201, IP: remote.IP}
	sdf := pfcp.SDFFilter{HasFlowDescription: true, FlowDescription: "permit out 17 from any 5061 to assigned 5060"}

	ies := []pfcp.IE{{Type: pfcp.IEPDNType, Value: []byte{1}}}
	ies = append(ies,
		testCreatePDR(t, 1, 100, pfcp.InterfaceAccess, ue, &local, true, nil, 1, 1, 1),
		testCreatePDR(t, 2, 100, pfcp.InterfaceCore, ue, nil, false, nil, 2, 1, 1),
		testCreateFAR(t, 1, pfcp.InterfaceCore, nil),
		testCreateFAR(t, 2, pfcp.InterfaceAccess, &remote),
		testCreateQER(t, 1, 0, 0, nil), testCreateURR(t, 1),
		testCreatePDR(t, 21, 50, pfcp.InterfaceAccess, ue, &dedicatedLocal, true, &sdf, 11, 2, 2),
		testCreatePDR(t, 22, 50, pfcp.InterfaceCore, ue, nil, false, &sdf, 12, 2, 2),
		testCreateFAR(t, 11, pfcp.InterfaceCore, nil),
		testCreateFAR(t, 12, pfcp.InterfaceAccess, &dedicatedRemote),
		testCreateQER(t, 2, 128_000, 256_000, &pfcp.BearerQoSMetadata{EnterpriseID: enterpriseID, QCI: 1, ARP: 2}),
		testCreateURR(t, 2),
	)

	decoded, err := server.decodeSession(ies, 10, 20)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.UplinkPDRID != 1 || decoded.DownlinkPDRID != 2 || decoded.UplinkFARID != 1 || decoded.DownlinkFARID != 2 || len(decoded.DedicatedBearers) != 1 {
		t.Fatalf("decoded session = %#v", decoded)
	}
	bearer := decoded.DedicatedBearers[0]
	if bearer.Local.TEID != 101 || bearer.Local.IP != server.config.DedicatedUserIP || bearer.Remote.TEID != 201 || bearer.QERID != 2 || bearer.URRID != 2 || bearer.QCI != 1 || bearer.ARP != 2 ||
		bearer.MaxUplinkBitsPerSecond != 128_000 || bearer.MaxDownlinkBitsPerSecond != 256_000 || len(bearer.Filters) != 2 {
		t.Fatalf("decoded dedicated bearer = %#v", bearer)
	}
	store := rules.NewStoreWithLimit(1)
	created, err := store.Create(decoded)
	if err != nil {
		t.Fatal(err)
	}
	downlinkVoice := testTransportPacket(ue, false, 5060, 5061)
	if rule, ok := store.LookupDownlinkPacket(ue, downlinkVoice); !ok || rule.Default || rule.Remote.TEID != 201 {
		t.Fatalf("downlink rule = %#v, %v", rule, ok)
	}
	uplinkVoice := testTransportPacket(ue, true, 5060, 5061)
	if rule, ok := store.LookupUplinkPacket(101, uplinkVoice); !ok || rule.Default || rule.UPSEID != created.UPSEID {
		t.Fatalf("uplink rule = %#v, %v", rule, ok)
	}
}

func TestDecodeSessionInfersQCI1WithoutPrivateMetadata(t *testing.T) {
	server := &Server{config: Config{
		UserIP: netip.MustParseAddr("10.200.0.20"), DedicatedUserIP: netip.MustParseAddr("10.200.0.21"),
	}}
	ue := netip.MustParseAddr("10.90.0.2")
	local := rules.Tunnel{TEID: 100, IP: server.config.UserIP}
	remote := rules.Tunnel{TEID: 200, IP: netip.MustParseAddr("10.200.0.10")}
	dedicatedLocal := rules.Tunnel{TEID: 101, IP: server.config.DedicatedUserIP}
	dedicatedRemote := rules.Tunnel{TEID: 201, IP: remote.IP}
	sdf := pfcp.SDFFilter{HasFlowDescription: true, FlowDescription: "permit out 17 from any 5061 to assigned 5060"}
	ies := []pfcp.IE{{Type: pfcp.IEPDNType, Value: []byte{1}}}
	ies = append(ies,
		testCreatePDR(t, 1, 100, pfcp.InterfaceAccess, ue, &local, true, nil, 1, 1, 1),
		testCreatePDR(t, 2, 100, pfcp.InterfaceCore, ue, nil, false, nil, 2, 1, 1),
		testCreateFAR(t, 1, pfcp.InterfaceCore, nil),
		testCreateFAR(t, 2, pfcp.InterfaceAccess, &remote),
		testCreateQER(t, 1, 0, 0, nil), testCreateURR(t, 1),
		testCreatePDR(t, 21, 50, pfcp.InterfaceAccess, ue, &dedicatedLocal, true, &sdf, 11, 2, 2),
		testCreatePDR(t, 22, 50, pfcp.InterfaceCore, ue, nil, false, &sdf, 12, 2, 2),
		testCreateFAR(t, 11, pfcp.InterfaceCore, nil),
		testCreateFAR(t, 12, pfcp.InterfaceAccess, &dedicatedRemote),
		testCreateQER(t, 2, 128_000, 256_000, nil), testCreateURR(t, 2),
	)

	decoded, err := server.decodeSession(ies, 10, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.DedicatedBearers) != 1 || decoded.DedicatedBearers[0].QCI != 1 || decoded.DedicatedBearers[0].ARP != 0 {
		t.Fatalf("standard Sxb QCI 1 inference = %#v", decoded.DedicatedBearers)
	}
	if _, err := rules.NewStoreWithLimit(1).Create(decoded); err != nil {
		t.Fatalf("store rejected standards-shaped dedicated bearer: %v", err)
	}
}

func TestDecodeSessionRejectsMixedOrUnreferencedDedicatedRules(t *testing.T) {
	server := &Server{config: Config{UserIP: netip.MustParseAddr("10.200.0.20")}}
	ue := netip.MustParseAddr("10.90.0.2")
	local := rules.Tunnel{TEID: 100, IP: server.config.UserIP}
	remote := rules.Tunnel{TEID: 200, IP: netip.MustParseAddr("10.200.0.10")}
	sdf := pfcp.SDFFilter{HasFlowDescription: true, FlowDescription: "permit out 17 from any to assigned 5060"}
	base := []pfcp.IE{
		{Type: pfcp.IEPDNType, Value: []byte{1}},
		testCreatePDR(t, 1, 100, pfcp.InterfaceAccess, ue, &local, true, nil, 1, 1, 1),
		testCreatePDR(t, 2, 100, pfcp.InterfaceCore, ue, nil, false, nil, 2, 1, 1),
		testCreateFAR(t, 1, pfcp.InterfaceCore, nil), testCreateFAR(t, 2, pfcp.InterfaceAccess, &remote),
		testCreateQER(t, 1, 0, 0, nil), testCreateURR(t, 1),
	}
	t.Run("mixed filtered and unfiltered", func(t *testing.T) {
		localDedicated, remoteDedicated := local, remote
		localDedicated.TEID, remoteDedicated.TEID = 101, 201
		ies := append([]pfcp.IE(nil), base...)
		ies = append(ies,
			testCreatePDR(t, 21, 50, pfcp.InterfaceAccess, ue, &localDedicated, true, &sdf, 11, 2, 2),
			testCreatePDR(t, 22, 50, pfcp.InterfaceCore, ue, nil, false, nil, 12, 2, 2),
			testCreateFAR(t, 11, pfcp.InterfaceCore, nil), testCreateFAR(t, 12, pfcp.InterfaceAccess, &remoteDedicated),
			testCreateQER(t, 2, 0, 0, nil), testCreateURR(t, 2),
		)
		if _, err := server.decodeSession(ies, 10, 20); err == nil {
			t.Fatal("mixed dedicated bearer was accepted")
		}
	})
	t.Run("unreferenced FAR", func(t *testing.T) {
		ies := append(append([]pfcp.IE(nil), base...), testCreateFAR(t, 99, pfcp.InterfaceCore, nil))
		if _, err := server.decodeSession(ies, 10, 20); err == nil {
			t.Fatal("unreferenced FAR was accepted")
		}
	})
}

func testCreatePDR(t *testing.T, id uint16, precedence uint32, source uint8, ue netip.Addr, local *rules.Tunnel, remove bool, sdf *pfcp.SDFFilter, farID, qerID, urrID uint32) pfcp.IE {
	t.Helper()
	idIE, _ := pfcp.NewPDRIDIE(id)
	precedenceIE, _ := pfcp.NewUint32IE(pfcp.IEPrecedence, precedence)
	sourceIE, _ := pfcp.NewInterfaceIE(pfcp.IESourceInterface, source)
	ueIE, _ := pfcp.NewUEIPAddressIE(ue, source == pfcp.InterfaceCore)
	pdiChildren := []pfcp.IE{sourceIE, ueIE}
	if local != nil {
		fteid, _ := pfcp.NewFTEIDIE(pfcp.FTEID{TEID: local.TEID, IPv4: local.IP})
		pdiChildren = append(pdiChildren, fteid)
	}
	if sdf != nil {
		sdfIE, err := pfcp.NewSDFFilterIE(*sdf)
		if err != nil {
			t.Fatal(err)
		}
		pdiChildren = append(pdiChildren, sdfIE)
	}
	pdi, _ := pfcp.NewGroupedIE(pfcp.IEPDI, pdiChildren...)
	far, _ := pfcp.NewUint32IE(pfcp.IEFARID, farID)
	qer, _ := pfcp.NewUint32IE(pfcp.IEQERID, qerID)
	urr, _ := pfcp.NewUint32IE(pfcp.IEURRID, urrID)
	children := []pfcp.IE{idIE, precedenceIE, pdi, far, qer, urr}
	if remove {
		removal, _ := pfcp.NewOuterHeaderRemovalIE(pfcp.OuterHeaderRemovalGTPUUDPIPv4)
		children = append(children, removal)
	}
	grouped, err := pfcp.NewGroupedIE(pfcp.IECreatePDR, children...)
	if err != nil {
		t.Fatal(err)
	}
	return grouped
}

func testCreateFAR(t *testing.T, id uint32, destination uint8, remote *rules.Tunnel) pfcp.IE {
	t.Helper()
	idIE, _ := pfcp.NewUint32IE(pfcp.IEFARID, id)
	action, _ := pfcp.NewApplyActionIE(pfcp.ApplyForward)
	destinationIE, _ := pfcp.NewInterfaceIE(pfcp.IEDestinationInterface, destination)
	parameters := []pfcp.IE{destinationIE}
	if remote != nil {
		outer, _ := pfcp.NewOuterHeaderCreationIE(pfcp.OuterHeader{Description: pfcp.OuterHeaderGTPUUDPIPv4, TEID: remote.TEID, IPv4: remote.IP})
		parameters = append(parameters, outer)
	}
	forwarding, _ := pfcp.NewGroupedIE(pfcp.IEForwardingParameters, parameters...)
	grouped, err := pfcp.NewGroupedIE(pfcp.IECreateFAR, idIE, action, forwarding)
	if err != nil {
		t.Fatal(err)
	}
	return grouped
}

func testCreateQER(t *testing.T, id uint32, uplink, downlink uint64, metadata *pfcp.BearerQoSMetadata) pfcp.IE {
	t.Helper()
	idIE, _ := pfcp.NewUint32IE(pfcp.IEQERID, id)
	children := []pfcp.IE{idIE, pfcp.NewGateStatusIE(true, true)}
	if uplink != 0 || downlink != 0 {
		mbr, _ := pfcp.NewBitRateIE(pfcp.IEMBR, uplink/1000, downlink/1000)
		children = append(children, mbr)
	}
	if metadata != nil {
		vendor, err := pfcp.NewVendorBearerQoSIE(*metadata)
		if err != nil {
			t.Fatal(err)
		}
		children = append(children, vendor)
	}
	grouped, err := pfcp.NewGroupedIE(pfcp.IECreateQER, children...)
	if err != nil {
		t.Fatal(err)
	}
	return grouped
}

func testCreateURR(t *testing.T, id uint32) pfcp.IE {
	t.Helper()
	idIE, _ := pfcp.NewUint32IE(pfcp.IEURRID, id)
	method, _ := pfcp.NewMeasurementMethodIE(true, true)
	trigger, _ := pfcp.NewReportingTriggersIE(pfcp.ReportingTriggerVolumeThreshold)
	threshold, _ := pfcp.NewTotalVolumeThresholdIE(1 << 30)
	grouped, err := pfcp.NewGroupedIE(pfcp.IECreateURR, idIE, method, trigger, threshold)
	if err != nil {
		t.Fatal(err)
	}
	return grouped
}

func testTransportPacket(ue netip.Addr, uplink bool, localPort, remotePort uint16) []byte {
	remote := netip.MustParseAddr("203.0.113.9")
	source, destination := remote, ue
	sourcePort, destinationPort := remotePort, localPort
	if uplink {
		source, destination = ue, remote
		sourcePort, destinationPort = localPort, remotePort
	}
	packet := make([]byte, 24)
	packet[0], packet[8], packet[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	sourceRaw, destinationRaw := source.As4(), destination.As4()
	copy(packet[12:16], sourceRaw[:])
	copy(packet[16:20], destinationRaw[:])
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], destinationPort)
	return packet
}
