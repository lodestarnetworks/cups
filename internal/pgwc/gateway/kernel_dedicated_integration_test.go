//go:build linux

package gateway

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	gtptransport "github.com/lodestarnetworks/cups/internal/gtpv2/transport"
	"github.com/lodestarnetworks/cups/internal/kernelgtp"
	pfcptransport "github.com/lodestarnetworks/cups/internal/pfcp/transport"
	"github.com/lodestarnetworks/cups/internal/pgwc/ipam"
	"github.com/lodestarnetworks/cups/internal/pgwc/pfcpclient"
	"github.com/lodestarnetworks/cups/internal/pgwc/session"
	pgwudataplane "github.com/lodestarnetworks/cups/internal/pgwu/dataplane"
	pgwupfcp "github.com/lodestarnetworks/cups/internal/pgwu/pfcpserver"
	pgwurules "github.com/lodestarnetworks/cups/internal/pgwu/rules"
	"github.com/lodestarnetworks/cups/pkg/gtpu"
	"github.com/lodestarnetworks/cups/pkg/gtpv2"
)

// TestFullStackKernelDedicatedBearerIntegration drives a PGW-initiated
// Create Bearer over real GTPv2-C and PFCP endpoints, commits it through the
// PGW-U rule store into dual Linux GTP devices, then proves QCI 1 traffic in
// both directions uses the dedicated tunnel. It must run only in the
// disposable namespace created by run-isolated-kernel-policy-test.sh.
func TestFullStackKernelDedicatedBearerIntegration(t *testing.T) {
	if os.Getenv("SGW_NEXT_KERNEL_GTP_TEST") != "1" {
		t.Skip("full-stack kernel dedicated-bearer test requires a disposable network namespace")
	}
	if os.Geteuid() != 0 {
		t.Fatal("full-stack kernel dedicated-bearer test requires root")
	}

	defaultOuter := netip.MustParseAddr("10.254.77.1")
	sgwUser := netip.MustParseAddr("10.254.77.2")
	serviceIP := netip.MustParseAddr("10.254.77.3")
	qci1Outer := netip.MustParseAddr("10.254.77.4")
	internetPrefix := netip.MustParsePrefix("10.254.200.0/24")
	imsPrefix := netip.MustParsePrefix("10.254.201.0/24")
	internetGateway := netip.MustParseAddr("10.254.200.1")
	imsGateway := netip.MustParseAddr("10.254.201.1")

	suffix := os.Getpid() % 100_000
	kernel, err := pgwudataplane.OpenKernel(pgwudataplane.KernelConfig{
		S5:              netip.AddrPortFrom(defaultOuter, kernelgtp.GTPUPort),
		QCI1S5:          netip.AddrPortFrom(qci1Outer, kernelgtp.GTPUPort),
		AllowedSGWPeers: []netip.Addr{sgwUser},
		TunnelName:      fmt.Sprintf("lodfs%d", suffix), QCI1TunnelName: fmt.Sprintf("lodf1%d", suffix),
		OwnershipFile: filepath.Join(t.TempDir(), "default.owner"), QCI1OwnershipFile: filepath.Join(t.TempDir(), "qci1.owner"),
		UEPools: []pgwudataplane.UEPool{
			{Prefix: internetPrefix, Gateway: internetGateway},
			{Prefix: imsPrefix, Gateway: imsGateway},
		},
		HashSize: 4_096, MTU: 1_400,
		SocketBufferBytes: 4 * 1024 * 1024, MaxSessions: 100, MaxPolicyFilters: 1_024,
		QERBurstDuration: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer kernel.Close()
	pgwuStore := pgwurules.NewStoreWithApplier(100, kernel)

	pfcpConfig := pfcptransport.DefaultConfig()
	pfcpConfig.RetransmitTimeout = 50 * time.Millisecond
	pfcpConfig.MaxRetransmits = 2
	pgwcPFCP := netip.MustParseAddr("127.127.0.1")
	pgwuPFCP := netip.MustParseAddr("127.127.0.2")
	upServer, err := pgwupfcp.New(pgwupfcp.Config{
		Listen: netip.AddrPortFrom(pgwuPFCP, 0), Advertise: pgwuPFCP,
		UserIP: defaultOuter, DedicatedUserIP: qci1Outer, AllowedCP: []netip.Addr{pgwcPFCP},
		Transport: pfcpConfig,
	}, pgwuStore)
	if err != nil {
		t.Fatal(err)
	}
	defer upServer.Close()
	upClient, err := pfcpclient.New(pfcpclient.Config{
		Listen: netip.AddrPortFrom(pgwcPFCP, 0), Advertise: pgwcPFCP,
		Remote: upServer.LocalAddr(), StartedAt: time.Now().UTC(), Transport: pfcpConfig,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer upClient.Close()

	gtpConfig := gtptransport.DefaultConfig()
	gtpConfig.RetransmitTimeout = 50 * time.Millisecond
	gtpConfig.MaxRetransmits = 2
	sgwControl := netip.MustParseAddr("127.126.0.2")
	pgwcControl := netip.MustParseAddr("127.126.0.1")
	peerHarness := &fakeSGWBearerPeer{userIP: sgwUser}
	peer, err := gtptransport.Listen(netip.AddrPortFrom(sgwControl, 2123), peerHarness.handle, gtpConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	internetPool, err := ipam.New(internetPrefix, internetGateway, 100)
	if err != nil {
		t.Fatal(err)
	}
	imsPool, err := ipam.New(imsPrefix, imsGateway, 100)
	if err != nil {
		t.Fatal(err)
	}
	control, err := New(Config{
		S5Listen: netip.AddrPortFrom(pgwcControl, 0), S5Advertise: pgwcControl,
		PGWUUserIP: defaultOuter, PGWUQCI1UserIP: qci1Outer, AllowedSGW: []netip.Addr{sgwControl},
		APNProfiles: []APNProfile{
			{APN: "internet", Pool: internetPool, DNSIPv4: []netip.Addr{netip.MustParseAddr("10.250.70.1"), netip.MustParseAddr("10.250.70.2")}, IPv4LinkMTU: 1400, APNAMBRUplinkBPS: 1_000_000_000, APNAMBRDownlinkBPS: 1_000_000_000},
			{APN: "ims", Pool: imsPool, DNSIPv4: []netip.Addr{netip.MustParseAddr("10.250.70.1"), netip.MustParseAddr("10.250.70.2")}, PCSCFIPv4: []netip.Addr{netip.MustParseAddr("10.250.70.3")}, IPv4LinkMTU: 1400, APNAMBRUplinkBPS: 100_000_000, APNAMBRDownlinkBPS: 100_000_000},
		},
		ProcedureTimeout: time.Second, SubscriberSalt: []byte("kernel-full-stack-test"), Transport: gtpConfig,
	}, session.NewStoreWithLimit(100), nil, upClient)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = upServer.Serve(ctx) }()
	go func() { _ = upClient.Serve(ctx) }()
	go func() { _ = peer.Serve(ctx) }()
	go func() { _ = control.Serve(ctx) }()
	operation, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	if err := upClient.Associate(operation); err != nil {
		t.Fatal(err)
	}

	createRequest := kernelDedicatedCreateRequestForAPN(t, sgwControl, sgwUser, "internet.mnc074.mcc901.gprs", 5, 0x2001, 0x3001)
	createResponse, err := peer.Do(operation, control.S5Addr(), createRequest)
	if err != nil || responseCause(t, createResponse) != gtpv2.CauseRequestAccepted {
		t.Fatalf("Create Session response=%#v error=%v", createResponse, err)
	}
	controlIE, ok := createResponse.Find(gtpv2.IEFTEID, 1)
	if !ok {
		t.Fatal("Create Session response omitted PGW control F-TEID")
	}
	pgwControl, err := controlIE.FTEID()
	if err != nil {
		t.Fatal(err)
	}
	peerHarness.setPGWControlTEID(pgwControl.TEID)
	imsRequest := kernelDedicatedCreateRequestForAPN(t, sgwControl, sgwUser, "ims.mnc074.mcc901.gprs", 6, 0x2002, 0x3002)
	imsResponse, err := peer.Do(operation, control.S5Addr(), imsRequest)
	if err != nil || responseCause(t, imsResponse) != gtpv2.CauseRequestAccepted {
		t.Fatalf("IMS Create Session response=%#v error=%v", imsResponse, err)
	}
	if got := responsePAA(t, imsResponse); !imsPrefix.Contains(got) {
		t.Fatalf("IMS PAA %s is outside %s", got, imsPrefix)
	}
	if values := responsePCOIPv4(t, imsResponse, gtpv2.PCOContainerPCSCFIPv4); len(values) != 1 || values[0] != netip.MustParseAddr("10.250.70.3") {
		t.Fatalf("IMS P-CSCF response = %v", values)
	}
	var current session.Session
	for _, candidate := range control.Sessions() {
		if candidate.APN == "internet" {
			current = candidate
		}
	}
	if current.ID == 0 || !internetPrefix.Contains(current.UEIPv4) || len(control.Sessions()) != 2 || pgwuStore.Count() != 2 {
		t.Fatalf("full-stack multi-APN state PGW-C=%#v PGW-U=%#v", control.Sessions(), pgwuStore.Snapshot())
	}
	dedicatedPlan := dedicatedBearerTestPlan()
	dedicatedPlan.EBI = 0
	created, err := control.CreateDedicatedBearer(operation, current.ID, dedicatedPlan)
	if err != nil {
		t.Fatal(err)
	}
	if created.PGWUser.IP != qci1Outer || len(pgwuStore.Snapshot()) != 2 || !hasPGWUDedicatedBearer(pgwuStore.Snapshot(), current.UEIPv4) {
		t.Fatalf("dedicated bearer did not reach kernel PGW-U: control=%#v user=%#v", created, pgwuStore.Snapshot())
	}

	userPeer, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(sgwUser, kernelgtp.GTPUPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer userPeer.Close()
	service, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(serviceIP, 5_061)))
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	if _, err := service.WriteToUDPAddrPort([]byte("full-stack-downlink"), netip.AddrPortFrom(current.UEIPv4, 5_060)); err != nil {
		t.Fatal(err)
	}
	if err := userPeer.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	outer := make([]byte, 2_048)
	n, source, err := userPeer.ReadFromUDPAddrPort(outer)
	if err != nil {
		t.Fatal(err)
	}
	header, _, err := gtpu.Parse(outer[:n])
	if err != nil {
		t.Fatal(err)
	}
	if source.Addr().Unmap() != qci1Outer || header.TEID != created.SGWUser.TEID {
		t.Fatalf("full-stack downlink source=%s TEID=%d, want %s/%d", source.Addr(), header.TEID, qci1Outer, created.SGWUser.TEID)
	}

	inner := kernelDedicatedIPv4UDP(current.UEIPv4, serviceIP, 5_060, 5_061, []byte("full-stack-uplink"))
	wire, err := gtpu.Marshal(gtpu.Header{
		Version: gtpu.Version, ProtocolType: true, MessageType: gtpu.MessageGPDU, TEID: created.PGWUser.TEID,
	}, inner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := userPeer.WriteToUDPAddrPort(wire, netip.AddrPortFrom(qci1Outer, kernelgtp.GTPUPort)); err != nil {
		t.Fatal(err)
	}
	if err := service.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 256)
	if n, _, err := service.ReadFromUDPAddrPort(payload); err != nil || string(payload[:max(n, 0)]) != "full-stack-uplink" {
		t.Fatalf("full-stack QCI 1 uplink payload=%q err=%v", payload[:max(n, 0)], err)
	}
}

func kernelDedicatedCreateRequest(t *testing.T, controlIP, userIP netip.Addr) gtpv2.Message {
	return kernelDedicatedCreateRequestForAPN(t, controlIP, userIP, "lodestartest.mnc074.mcc901.gprs", 5, 0x2001, 0x3001)
}

func kernelDedicatedCreateRequestForAPN(t *testing.T, controlIP, userIP netip.Addr, apn string, ebi uint8, controlTEID, userTEID uint32) gtpv2.Message {
	t.Helper()
	request := makeCreateRequestForAPN(t, controlIP, apn, ebi, controlTEID, userTEID)
	for index := range request.IEs {
		if request.IEs[index].Type != gtpv2.IEBearerContext || request.IEs[index].Instance != 0 {
			continue
		}
		children, err := request.IEs[index].Children()
		if err != nil {
			t.Fatal(err)
		}
		for child := range children {
			if children[child].Type == gtpv2.IEFTEID && children[child].Instance == 2 {
				children[child], err = gtpv2.NewFTEIDIE(2, gtpv2.FTEID{
					InterfaceType: gtpv2.InterfaceS5S8SGWGTPU, TEID: userTEID, IPv4: userIP,
				})
				if err != nil {
					t.Fatal(err)
				}
			}
		}
		request.IEs[index], err = gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, children...)
		if err != nil {
			t.Fatal(err)
		}
	}
	return request
}

func hasPGWUDedicatedBearer(sessions []pgwurules.Session, ueIPv4 netip.Addr) bool {
	for _, current := range sessions {
		if current.UEIPv4 == ueIPv4 && len(current.DedicatedBearers) == 1 {
			return true
		}
	}
	return false
}

func kernelDedicatedIPv4UDP(source, destination netip.Addr, sourcePort, destinationPort uint16, payload []byte) []byte {
	packet := make([]byte, 20+8+len(payload))
	packet[0], packet[8], packet[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[4:6], 1)
	sourceRaw, destinationRaw := source.As4(), destination.As4()
	copy(packet[12:16], sourceRaw[:])
	copy(packet[16:20], destinationRaw[:])
	binary.BigEndian.PutUint16(packet[10:12], kernelDedicatedIPv4Checksum(packet[:20]))
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], destinationPort)
	binary.BigEndian.PutUint16(packet[24:26], uint16(8+len(payload)))
	copy(packet[28:], payload)
	return packet
}

func kernelDedicatedIPv4Checksum(header []byte) uint16 {
	var sum uint32
	for index := 0; index+1 < len(header); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[index : index+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
