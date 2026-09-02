//go:build linux

package kernelgtp

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
	"golang.org/x/sys/unix"

	"github.com/lodestarnetworks/cups/pkg/gtpu"
)

const kernelIntegrationEnvironment = "SGW_NEXT_KERNEL_GTP_TEST"

const (
	kernelCrashHelperEnvironment = "SGW_NEXT_KERNEL_GTP_CRASH_HELPER"
	kernelCrashOwnerEnvironment  = "SGW_NEXT_KERNEL_GTP_CRASH_OWNER"
	kernelCrashLinkEnvironment   = "SGW_NEXT_KERNEL_GTP_CRASH_LINK"
)

// TestKernelGTPControllerIntegration creates a real kernel GTP device, proves
// generic-netlink context CRUD, and exchanges one packet in each direction.
// The surrounding runner must place the test in a disposable network namespace
// with the three documented 10.x addresses on loopback.
func TestKernelGTPControllerIntegration(t *testing.T) {
	if os.Getenv(kernelIntegrationEnvironment) != "1" {
		t.Skipf("set %s=1 inside a disposable network namespace", kernelIntegrationEnvironment)
	}
	if os.Geteuid() != 0 {
		t.Fatal("kernel GTP integration test requires root in an isolated network namespace")
	}

	localOuter := netip.MustParseAddr("10.254.77.1")
	peerOuter := netip.MustParseAddr("10.254.77.2")
	serviceIP := netip.MustParseAddr("10.254.77.3")
	ueGateway := netip.MustParseAddr("10.254.200.1")
	ueIP := netip.MustParseAddr("10.254.200.7")
	for _, address := range []netip.Addr{localOuter, peerOuter, serviceIP} {
		listener, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(address, 0)))
		if err != nil {
			t.Fatalf("required isolated address %s is unavailable: %v", address, err)
		}
		_ = listener.Close()
	}

	controller, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()

	linkName := fmt.Sprintf("lodgtp%d", os.Getpid()%100_000)
	link, err := controller.CreateLink(LinkConfig{
		Name: linkName, OwnershipFile: filepath.Join(t.TempDir(), "kernel.owner"),
		LocalIPv4: localOuter, AllowedPeers: []netip.Addr{peerOuter}, Role: RoleGGSN,
		HashSize: DefaultHashSize, MTU: 1_400, SocketBufferBytes: 4 * 1024 * 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := controller.DeleteLink(linkName); err != nil {
			t.Errorf("delete integration GTP link: %v", err)
		}
	}()
	if link.Kind != "gtp" || !isOwnershipAlias(link.Alias) || link.Role != RoleGGSN || link.MTU != 1_400 {
		t.Fatalf("unexpected link metadata: %+v", link)
	}
	state, err := os.ReadFile("/proc/sys/net/ipv6/conf/" + linkName + "/disable_ipv6")
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("read GTP IPv6 policy: %v", err)
	}
	if err == nil && string(state) != "1\n" {
		t.Fatalf("IPv6 was not disabled on IPv4-only GTP link: %q", state)
	}
	if err := controller.ConfigureIPv4(link, ueGateway, netip.MustParsePrefix("10.254.200.0/24")); err != nil {
		t.Fatal(err)
	}

	context := Context{
		LinkIndex: link.Index, UEIPv4: ueIP, PeerIPv4: peerOuter,
		IncomingTEID: 1_001, OutgoingTEID: 2_001,
	}
	if err := controller.AddContext(context); err != nil {
		t.Fatal(err)
	}
	got, err := controller.GetContext(link.Index, context.IncomingTEID)
	if err != nil {
		t.Fatal(err)
	}
	if got != context {
		t.Fatalf("context mismatch: got %+v want %+v", got, context)
	}
	changed, err := controller.EnsureContext(context)
	if err != nil || changed {
		t.Fatalf("idempotent ensure: changed=%v err=%v", changed, err)
	}
	context.OutgoingTEID = 2_002
	changed, err = controller.EnsureContext(context)
	if err != nil || !changed {
		t.Fatalf("peer tunnel update: changed=%v err=%v", changed, err)
	}
	report, err := controller.Reconcile(link.Index, []Context{context})
	if err != nil {
		t.Fatal(err)
	}
	if report.Unchanged != 1 || report.Created != 0 || report.Updated != 0 || report.Deleted != 0 {
		t.Fatalf("unexpected no-op reconciliation report: %+v", report)
	}

	peer, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(peerOuter, GTPUPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	uplinkReceiver, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(serviceIP, 39_001)))
	if err != nil {
		t.Fatal(err)
	}
	defer uplinkReceiver.Close()
	uplinkPayload := []byte("lodestar-kernel-gtp-uplink")
	innerUplink := buildIPv4UDP(ueIP, serviceIP, 39_000, 39_001, uplinkPayload)
	gtpUplink, err := gtpu.Marshal(gtpu.Header{
		Version: gtpu.Version, ProtocolType: true, MessageType: gtpu.MessageGPDU, TEID: context.IncomingTEID,
	}, innerUplink)
	if err != nil {
		t.Fatal(err)
	}
	unauthorized, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(serviceIP, GTPUPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer unauthorized.Close()
	if _, err := unauthorized.WriteToUDPAddrPort(gtpUplink, netip.AddrPortFrom(localOuter, GTPUPort)); err != nil {
		t.Fatal(err)
	}
	if err := uplinkReceiver.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	uplinkBuffer := make([]byte, 256)
	if _, _, err := uplinkReceiver.ReadFromUDPAddrPort(uplinkBuffer); err == nil {
		t.Fatal("non-allowlisted GTP-U peer bypassed the nftables filter")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("wait for filtered unauthorized packet: %v", err)
	}
	if _, err := peer.WriteToUDPAddrPort(gtpUplink, netip.AddrPortFrom(localOuter, GTPUPort)); err != nil {
		t.Fatal(err)
	}
	if err := uplinkReceiver.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, source, err := uplinkReceiver.ReadFromUDPAddrPort(uplinkBuffer)
	if err != nil {
		t.Fatalf("receive decapsulated uplink: %v", err)
	}
	if source.Addr().Unmap() != ueIP || string(uplinkBuffer[:n]) != string(uplinkPayload) {
		t.Fatalf("unexpected decapsulated uplink from %s: %q", source, uplinkBuffer[:n])
	}

	downlinkSender, err := net.DialUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(serviceIP, 39_002)), net.UDPAddrFromAddrPort(netip.AddrPortFrom(ueIP, 39_003)))
	if err != nil {
		t.Fatal(err)
	}
	defer downlinkSender.Close()
	downlinkPayload := []byte("lodestar-kernel-gtp-downlink")
	if _, err := downlinkSender.Write(downlinkPayload); err != nil {
		t.Fatal(err)
	}
	if err := peer.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	downlinkBuffer := make([]byte, 2_048)
	n, outerSource, err := peer.ReadFromUDPAddrPort(downlinkBuffer)
	if err != nil {
		t.Fatalf("receive encapsulated downlink: %v", err)
	}
	if outerSource.Addr().Unmap() != localOuter {
		t.Fatalf("unexpected downlink outer source: %s", outerSource)
	}
	header, innerDownlink, err := gtpu.Parse(downlinkBuffer[:n])
	if err != nil {
		t.Fatal(err)
	}
	if header.MessageType != gtpu.MessageGPDU || header.TEID != context.OutgoingTEID {
		t.Fatalf("unexpected downlink GTP header: %+v", header)
	}
	destination, payload, err := parseIPv4UDP(innerDownlink)
	if err != nil {
		t.Fatal(err)
	}
	if destination != ueIP || string(payload) != string(downlinkPayload) {
		t.Fatalf("unexpected encapsulated downlink to %s: %q", destination, payload)
	}
	filterCounters, err := controller.PeerFilterCounters(link)
	if err != nil {
		t.Fatal(err)
	}
	if filterCounters.AllowedPackets < 1 || filterCounters.DroppedPackets < 1 {
		t.Fatalf("unexpected GTP-U peer-filter counters: %+v", filterCounters)
	}

	report, err = controller.Reconcile(link.Index, nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.Deleted != 1 {
		t.Fatalf("expected one stale context deletion, got %+v", report)
	}
	contexts, err := controller.ListContexts(link.Index)
	if err != nil {
		t.Fatal(err)
	}
	if len(contexts) != 0 {
		t.Fatalf("contexts leaked after reconciliation: %+v", contexts)
	}
	if err := controller.DeleteLink(linkName); err != nil {
		t.Fatalf("delete integration GTP link: %v", err)
	}
	filterConnection, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	filterExists, err := nftTableExists(filterConnection, peerFirewallTablePrefix+linkName)
	if err != nil {
		t.Fatal(err)
	}
	if filterExists {
		t.Fatal("GTP-U peer-filter table leaked after link deletion")
	}
}

// TestKernelGTPPolicyRoutingIntegration proves the kernel primitive used by
// the PGW-U dedicated-bearer layer: a firewall mark selects a separate FIB
// table whose UE-pool route points at the QCI 1 GTP device. Unmarked traffic
// remains on the default device, so each device's PDP context supplies the
// correct bearer TEID without an unsafe cross-device TC redirect.
func TestKernelGTPPolicyRoutingIntegration(t *testing.T) {
	if os.Getenv(kernelIntegrationEnvironment) != "1" {
		t.Skipf("set %s=1 inside a disposable network namespace", kernelIntegrationEnvironment)
	}
	if os.Geteuid() != 0 {
		t.Fatal("kernel GTP bearer-class integration test requires root in an isolated network namespace")
	}
	defaultOuter := netip.MustParseAddr("10.254.77.1")
	peerOuter := netip.MustParseAddr("10.254.77.2")
	serviceIP := netip.MustParseAddr("10.254.77.3")
	qci1Outer := netip.MustParseAddr("10.254.77.4")
	uePools := []netip.Prefix{
		netip.MustParsePrefix("10.254.200.0/24"),
		netip.MustParsePrefix("10.254.201.0/24"),
	}
	ueGateways := []netip.Addr{
		netip.MustParseAddr("10.254.200.1"),
		netip.MustParseAddr("10.254.201.1"),
	}
	ueIPs := []netip.Addr{
		netip.MustParseAddr("10.254.200.7"),
		netip.MustParseAddr("10.254.201.7"),
	}

	controller, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()

	suffix := os.Getpid() % 100_000
	defaultName := fmt.Sprintf("loddf%d", suffix)
	qci1Name := fmt.Sprintf("lodq1%d", suffix)
	defaultLink, err := controller.CreateLink(LinkConfig{
		Name: defaultName, OwnershipFile: filepath.Join(t.TempDir(), "default.owner"),
		LocalIPv4: defaultOuter, AllowedPeers: []netip.Addr{peerOuter}, Role: RoleGGSN,
		HashSize: 4_096, MTU: 1_400, SocketBufferBytes: 4 * 1024 * 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	qci1Link, err := controller.CreateLink(LinkConfig{
		Name: qci1Name, OwnershipFile: filepath.Join(t.TempDir(), "qci1.owner"),
		LocalIPv4: qci1Outer, AllowedPeers: []netip.Addr{peerOuter}, Role: RoleGGSN,
		HashSize: 4_096, MTU: 1_400, SocketBufferBytes: 4 * 1024 * 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	for index := range uePools {
		if err := controller.ConfigureIPv4(defaultLink, ueGateways[index], uePools[index]); err != nil {
			t.Fatal(err)
		}
	}
	policyConfig := PolicyRoutingConfig{Table: 21_521, Priority: 10_510, Mark: 0x4c51_0000, Mask: 0xffff_0000}
	if _, err := controller.ConfigurePolicyIPv4Prefixes(qci1Link, uePools, policyConfig); err != nil {
		t.Fatal(err)
	}

	defaultContexts := make([]Context, len(ueIPs))
	qci1Contexts := make([]Context, len(ueIPs))
	for index, ueIP := range ueIPs {
		defaultContexts[index] = Context{
			LinkIndex: defaultLink.Index, UEIPv4: ueIP, PeerIPv4: peerOuter,
			IncomingTEID: uint32(1_001 + index*10), OutgoingTEID: uint32(2_001 + index*10),
		}
		qci1Contexts[index] = Context{
			LinkIndex: qci1Link.Index, UEIPv4: ueIP, PeerIPv4: peerOuter,
			IncomingTEID: uint32(1_002 + index*10), OutgoingTEID: uint32(2_002 + index*10),
		}
		if err := controller.AddContext(defaultContexts[index]); err != nil {
			t.Fatal(err)
		}
		if err := controller.AddContext(qci1Contexts[index]); err != nil {
			t.Fatal(err)
		}
	}
	routes, err := controller.listIPv4Routes(policyConfig.Table)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != len(uePools) {
		t.Fatalf("QCI 1 policy routes=%+v, want one exact route per UE pool", routes)
	}
	routedPools := make(map[netip.Prefix]bool, len(routes))
	for _, route := range routes {
		if route.outputIndex != qci1Link.Index {
			t.Fatalf("QCI 1 policy route %+v uses the wrong output link", route)
		}
		routedPools[route.prefix] = true
	}
	for _, pool := range uePools {
		if !routedPools[pool] {
			t.Fatalf("QCI 1 policy table is missing exact UE pool %s: %+v", pool, routes)
		}
	}

	peer, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(peerOuter, GTPUPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	assertDownlink := func(ueIP netip.Addr, destinationPort uint16, mark uint32, expectedSource netip.Addr, expectedTEID uint32) {
		t.Helper()
		sender, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(serviceIP, 0)))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := sender.SyscallConn()
		if err != nil {
			_ = sender.Close()
			t.Fatal(err)
		}
		var markErr error
		if err := raw.Control(func(fd uintptr) {
			markErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
		}); err != nil {
			_ = sender.Close()
			t.Fatal(err)
		}
		if markErr != nil {
			_ = sender.Close()
			t.Fatal(markErr)
		}
		if _, err := sender.WriteToUDPAddrPort([]byte("lodestar-bearer-class"), netip.AddrPortFrom(ueIP, destinationPort)); err != nil {
			_ = sender.Close()
			t.Fatal(err)
		}
		_ = sender.Close()
		if err := peer.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 2_048)
		n, source, err := peer.ReadFromUDPAddrPort(buffer)
		if err != nil {
			t.Fatal(err)
		}
		header, inner, err := gtpu.Parse(buffer[:n])
		if err != nil {
			t.Fatal(err)
		}
		if source.Addr().Unmap() != expectedSource || header.TEID != expectedTEID {
			t.Fatalf("downlink port %d used source=%s TEID=%d, want source=%s TEID=%d", destinationPort, source.Addr(), header.TEID, expectedSource, expectedTEID)
		}
		destination, payload, err := parseIPv4UDP(inner)
		if err != nil {
			t.Fatal(err)
		}
		if destination != ueIP || string(payload) != "lodestar-bearer-class" {
			t.Fatalf("unexpected policy-routed inner packet destination=%s payload=%q", destination, payload)
		}
	}

	for index, ueIP := range ueIPs {
		assertDownlink(ueIP, uint16(5_060+index*2), policyConfig.Mark, qci1Outer, qci1Contexts[index].OutgoingTEID)
		assertDownlink(ueIP, uint16(5_061+index*2), 0, defaultOuter, defaultContexts[index].OutgoingTEID)
	}

	if err := controller.DeleteLink(qci1Name); err != nil {
		t.Fatal(err)
	}
	routes, err = controller.listIPv4Routes(policyConfig.Table)
	if err != nil || len(routes) != 0 {
		t.Fatalf("QCI 1 policy route cleanup routes=%+v err=%v", routes, err)
	}
	policyRules, err := controller.listIPv4PolicyRules()
	if err != nil {
		t.Fatal(err)
	}
	for _, policyRule := range policyRules {
		if samePolicyRule(policyRule, policyConfig) {
			t.Fatal("QCI 1 policy rule survived owned link deletion")
		}
	}
}

func TestKernelGTPControllerSessionChurn(t *testing.T) {
	if os.Getenv(kernelIntegrationEnvironment) != "1" {
		t.Skipf("set %s=1 inside a disposable network namespace", kernelIntegrationEnvironment)
	}
	if os.Geteuid() != 0 {
		t.Fatal("kernel GTP integration test requires root in an isolated network namespace")
	}

	localOuter := netip.MustParseAddr("10.254.77.1")
	peerOuter := netip.MustParseAddr("10.254.77.2")
	controller, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	linkName := fmt.Sprintf("lodchr%d", os.Getpid()%100_000)
	link, err := controller.CreateLink(LinkConfig{
		Name: linkName, OwnershipFile: filepath.Join(t.TempDir(), "kernel.owner"),
		LocalIPv4: localOuter, AllowedPeers: []netip.Addr{peerOuter}, Role: RoleGGSN,
		HashSize: DefaultHashSize, MTU: 1_400, SocketBufferBytes: 4 * 1024 * 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer controller.DeleteLink(linkName)

	sessionCount := 1_000
	if raw := os.Getenv("SGW_NEXT_KERNEL_GTP_CHURN_SESSIONS"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 1_000_000 {
			t.Fatalf("SGW_NEXT_KERNEL_GTP_CHURN_SESSIONS must be between 1 and 1000000, got %q", raw)
		}
		sessionCount = parsed
	}
	started := time.Now()
	for index := 1; index <= sessionCount; index++ {
		ue := netip.AddrFrom4([4]byte{10, byte(index >> 16), byte(index >> 8), byte(index)})
		if err := controller.AddContext(Context{
			LinkIndex: link.Index, UEIPv4: ue, PeerIPv4: peerOuter,
			IncomingTEID: uint32(1_000_000 + index), OutgoingTEID: uint32(2_000_000 + index),
		}); err != nil {
			t.Fatalf("add context %d: %v", index, err)
		}
	}
	createElapsed := time.Since(started)
	contexts, err := controller.ListContexts(link.Index)
	if err != nil {
		t.Fatal(err)
	}
	if len(contexts) != sessionCount {
		t.Fatalf("kernel context count after churn create = %d, want %d", len(contexts), sessionCount)
	}

	started = time.Now()
	report, err := controller.Reconcile(link.Index, nil)
	if err != nil {
		t.Fatal(err)
	}
	deleteElapsed := time.Since(started)
	if report.Deleted != sessionCount {
		t.Fatalf("deleted context count = %d, want %d", report.Deleted, sessionCount)
	}
	contexts, err = controller.ListContexts(link.Index)
	if err != nil {
		t.Fatal(err)
	}
	if len(contexts) != 0 {
		t.Fatalf("kernel context orphans after churn = %d", len(contexts))
	}
	t.Logf("%d-session kernel churn: create %.3f ms (%.0f sessions/s), delete %.3f ms (%.0f sessions/s), orphans 0",
		sessionCount, float64(createElapsed.Microseconds())/1000, float64(sessionCount)/createElapsed.Seconds(),
		float64(deleteElapsed.Microseconds())/1000, float64(sessionCount)/deleteElapsed.Seconds())

	if err := controller.DeleteLink(linkName); err != nil {
		t.Fatal(err)
	}
	connection, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	exists, err := nftTableExists(connection, peerFirewallTablePrefix+linkName)
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("GTP-U peer-filter table orphaned after churn")
	}
}

// TestKernelGTPControllerAbruptCrashRecovery runs a real child process which
// owns the socket, GTP device, nftables table, and flock, then kills it with
// SIGKILL. Restart must preserve the durable token, reclaim only those exact
// stale objects, and leave no resources after a subsequent clean shutdown.
func TestKernelGTPControllerAbruptCrashRecovery(t *testing.T) {
	if os.Getenv(kernelIntegrationEnvironment) != "1" {
		t.Skipf("set %s=1 inside a disposable network namespace", kernelIntegrationEnvironment)
	}
	if os.Geteuid() != 0 {
		t.Fatal("kernel GTP integration test requires root in an isolated network namespace")
	}
	linkName := fmt.Sprintf("lodkill%d", os.Getpid()%100_000)
	ownerPath := filepath.Join(t.TempDir(), "kernel.owner")
	config := crashRecoveryLinkConfig(linkName, ownerPath)

	command := exec.Command(os.Args[0], "-test.run=^TestKernelGTPCrashHelper$", "-test.count=1")
	command.Env = append(os.Environ(),
		kernelCrashHelperEnvironment+"=1",
		kernelCrashOwnerEnvironment+"="+ownerPath,
		kernelCrashLinkEnvironment+"="+linkName,
	)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			ready <- scanner.Text()
			return
		}
		ready <- ""
	}()
	var originalAlias string
	select {
	case line := <-ready:
		parts := strings.Fields(line)
		if len(parts) != 2 || parts[0] != "READY" || !isOwnershipAlias(parts[1]) {
			_ = command.Process.Kill()
			_ = command.Wait()
			t.Fatalf("crash helper did not become ready: stdout=%q stderr=%q", line, stderr.String())
		}
		originalAlias = parts[1]
	case <-time.After(10 * time.Second):
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("timed out waiting for crash helper: %s", stderr.String())
	}

	contender, err := Open()
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal(err)
	}
	if _, err := contender.CreateLink(config); !errors.Is(err, ErrOwnerActive) {
		_ = contender.Close()
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("concurrent owner error = %v, want ErrOwnerActive", err)
	}
	if err := contender.Close(); err != nil {
		t.Fatal(err)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("crash helper exited cleanly after SIGKILL")
	}

	restarted, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	link, err := restarted.CreateLink(config)
	if err != nil {
		_ = restarted.Close()
		t.Fatalf("recover after abrupt crash: %v (helper stderr: %s)", err, stderr.String())
	}
	if link.Alias != originalAlias {
		_ = restarted.Close()
		t.Fatalf("recovered owner alias = %q, want %q", link.Alias, originalAlias)
	}
	if !link.Recovery.LinkRemoved || !link.Recovery.PeerFilterRemoved {
		_ = restarted.Close()
		t.Fatalf("abrupt-crash recovery report = %+v, want both stale resources removed", link.Recovery)
	}
	if err := restarted.Close(); err != nil {
		t.Fatal(err)
	}
	if _, exists, err := findInterface(linkName); err != nil || exists {
		t.Fatalf("GTP interface after clean recovered shutdown: exists=%v err=%v", exists, err)
	}
	connection, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	if exists, err := nftTableExists(connection, peerFirewallTablePrefix+linkName); err != nil || exists {
		t.Fatalf("peer-filter table after clean recovered shutdown: exists=%v err=%v", exists, err)
	}
}

func TestKernelGTPCrashHelper(t *testing.T) {
	if os.Getenv(kernelCrashHelperEnvironment) != "1" {
		t.Skip("crash helper is started only by the parent integration test")
	}
	controller, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	link, err := controller.CreateLink(crashRecoveryLinkConfig(
		os.Getenv(kernelCrashLinkEnvironment), os.Getenv(kernelCrashOwnerEnvironment),
	))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("READY %s\n", link.Alias)
	if err := os.Stdout.Sync(); err != nil {
		t.Fatal(err)
	}
	select {}
}

func TestKernelGTPControllerRefusesForeignResources(t *testing.T) {
	if os.Getenv(kernelIntegrationEnvironment) != "1" {
		t.Skipf("set %s=1 inside a disposable network namespace", kernelIntegrationEnvironment)
	}
	if os.Geteuid() != 0 {
		t.Fatal("kernel GTP integration test requires root in an isolated network namespace")
	}
	localOuter := netip.MustParseAddr("10.254.77.1")
	peerOuter := netip.MustParseAddr("10.254.77.2")

	t.Run("different durable token", func(t *testing.T) {
		linkName := fmt.Sprintf("lodtok%d", os.Getpid()%100_000)
		first, err := Open()
		if err != nil {
			t.Fatal(err)
		}
		firstLink, err := first.CreateLink(LinkConfig{
			Name: linkName, OwnershipFile: filepath.Join(t.TempDir(), "first.owner"),
			LocalIPv4: localOuter, AllowedPeers: []netip.Addr{peerOuter}, Role: RoleGGSN,
		})
		if err != nil {
			_ = first.Close()
			t.Fatal(err)
		}
		second, err := Open()
		if err != nil {
			_ = first.Close()
			t.Fatal(err)
		}
		_, createErr := second.CreateLink(LinkConfig{
			Name: linkName, OwnershipFile: filepath.Join(t.TempDir(), "second.owner"),
			LocalIPv4: localOuter, AllowedPeers: []netip.Addr{peerOuter}, Role: RoleGGSN,
		})
		if !errors.Is(createErr, ErrNotOwned) {
			_ = second.Close()
			_ = first.Close()
			t.Fatalf("different-token recovery error = %v, want ErrNotOwned", createErr)
		}
		preserved, err := first.InspectLink(linkName)
		if err != nil || preserved.Index != firstLink.Index || preserved.Alias != firstLink.Alias {
			_ = second.Close()
			_ = first.Close()
			t.Fatalf("foreign-token attempt mutated active link: got %+v err=%v", preserved, err)
		}
		if err := second.Close(); err != nil {
			t.Fatal(err)
		}
		if err := first.Close(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("different interface type", func(t *testing.T) {
		linkName := fmt.Sprintf("loddum%d", os.Getpid()%100_000)
		if output, err := exec.Command("ip", "link", "add", linkName, "type", "dummy").CombinedOutput(); err != nil {
			t.Fatalf("create foreign dummy interface: %v: %s", err, output)
		}
		defer exec.Command("ip", "link", "delete", linkName).Run()
		controller, err := Open()
		if err != nil {
			t.Fatal(err)
		}
		_, createErr := controller.CreateLink(LinkConfig{
			Name: linkName, OwnershipFile: filepath.Join(t.TempDir(), "kernel.owner"),
			LocalIPv4: localOuter, AllowedPeers: []netip.Addr{peerOuter}, Role: RoleGGSN,
		})
		if !errors.Is(createErr, ErrNotOwned) {
			_ = controller.Close()
			t.Fatalf("foreign-interface recovery error = %v, want ErrNotOwned", createErr)
		}
		if _, exists, err := findInterface(linkName); err != nil || !exists {
			_ = controller.Close()
			t.Fatalf("foreign dummy interface was not preserved: exists=%v err=%v", exists, err)
		}
		if err := controller.Close(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("unowned firewall table", func(t *testing.T) {
		linkName := fmt.Sprintf("lodnft%d", os.Getpid()%100_000)
		connection, err := nftables.New()
		if err != nil {
			t.Fatal(err)
		}
		table := connection.CreateTable(&nftables.Table{Name: peerFirewallTablePrefix + linkName, Family: nftables.TableFamilyIPv4})
		if err := connection.Flush(); err != nil {
			t.Fatal(err)
		}
		defer func() {
			cleanup, err := nftables.New()
			if err == nil {
				cleanup.DelTable(table)
				_ = cleanup.Flush()
			}
		}()
		controller, err := Open()
		if err != nil {
			t.Fatal(err)
		}
		_, createErr := controller.CreateLink(LinkConfig{
			Name: linkName, OwnershipFile: filepath.Join(t.TempDir(), "kernel.owner"),
			LocalIPv4: localOuter, AllowedPeers: []netip.Addr{peerOuter}, Role: RoleGGSN,
		})
		if !errors.Is(createErr, ErrNotOwned) {
			_ = controller.Close()
			t.Fatalf("foreign-firewall recovery error = %v, want ErrNotOwned", createErr)
		}
		probe, err := nftables.New()
		if err != nil {
			t.Fatal(err)
		}
		if exists, err := nftTableExists(probe, table.Name); err != nil || !exists {
			_ = controller.Close()
			t.Fatalf("foreign firewall was not preserved: exists=%v err=%v", exists, err)
		}
		if err := controller.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

func crashRecoveryLinkConfig(linkName, ownerPath string) LinkConfig {
	return LinkConfig{
		Name: linkName, OwnershipFile: ownerPath,
		LocalIPv4:    netip.MustParseAddr("10.254.77.1"),
		AllowedPeers: []netip.Addr{netip.MustParseAddr("10.254.77.2")},
		Role:         RoleGGSN, HashSize: 4_096, MTU: 1_400, SocketBufferBytes: 4 * 1024 * 1024,
	}
}

func buildIPv4UDP(source, destination netip.Addr, sourcePort, destinationPort uint16, payload []byte) []byte {
	packet := make([]byte, 20+8+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[4:6], 1)
	packet[8] = 64
	packet[9] = 17
	sourceRaw := source.As4()
	destinationRaw := destination.As4()
	copy(packet[12:16], sourceRaw[:])
	copy(packet[16:20], destinationRaw[:])
	binary.BigEndian.PutUint16(packet[10:12], ipv4Checksum(packet[:20]))
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], destinationPort)
	binary.BigEndian.PutUint16(packet[24:26], uint16(8+len(payload)))
	copy(packet[28:], payload)
	return packet
}

func parseIPv4UDP(packet []byte) (netip.Addr, []byte, error) {
	if len(packet) < 28 || packet[0]>>4 != 4 || packet[9] != 17 {
		return netip.Addr{}, nil, fmt.Errorf("invalid inner IPv4/UDP packet")
	}
	headerLength := int(packet[0]&0x0f) * 4
	if headerLength < 20 || headerLength+8 > len(packet) || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) {
		return netip.Addr{}, nil, fmt.Errorf("invalid inner IPv4 lengths")
	}
	udpLength := int(binary.BigEndian.Uint16(packet[headerLength+4 : headerLength+6]))
	if udpLength < 8 || headerLength+udpLength != len(packet) {
		return netip.Addr{}, nil, fmt.Errorf("invalid inner UDP length")
	}
	var raw [4]byte
	copy(raw[:], packet[16:20])
	return netip.AddrFrom4(raw), packet[headerLength+8:], nil
}

func ipv4Checksum(header []byte) uint16 {
	var sum uint32
	for index := 0; index+1 < len(header); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[index : index+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
