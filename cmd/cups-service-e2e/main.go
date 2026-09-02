package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	gtptransport "github.com/lodestarnetworks/cups/internal/gtpv2/transport"
	"github.com/lodestarnetworks/cups/internal/lab/epc"
)

func main() {
	mme := flag.String("mme", "10.253.10.2:2123", "synthetic MME GTPv2-C address")
	sgw := flag.String("sgw-s11", "10.253.10.1:2123", "running SGW-C S11 address")
	enodeb := flag.String("enodeb-user", "10.253.40.2:2152", "synthetic eNodeB GTP-U address")
	external := flag.String("external-user", "10.253.80.2:40001", "synthetic external-host UDP address")
	imsi := flag.String("imsi", "001010123456789", "synthetic IMSI")
	apn := flag.String("apn", "lodestartest", "APN")
	timeout := flag.Duration("timeout", 5*time.Second, "per-procedure and packet timeout")
	holdAfterModify := flag.Duration("hold-after-modify", 0, "keep the bearer active before user-plane checks")
	holdAfterData := flag.Duration("hold-after-data", 0, "keep the bearer active after user-plane checks")
	throughputDuration := flag.Duration("throughput-duration", 0, "sustained running-service load duration; zero disables")
	direction := flag.String("direction", "both", "load direction: uplink, downlink, or both")
	payloadSize := flag.Int("payload-size", 1200, "inner IPv4 packet bytes used for Mbps accounting")
	targetPPS := flag.Int("target-pps", 10_000, "offered packets/s per enabled direction; zero sends unpaced")
	packetBatchSize := flag.Int("packet-batch-size", 128, "UDP datagrams per sendmmsg/recvmmsg batch")
	mmeTEID := flag.Uint("mme-teid", 0x7a000001, "synthetic MME S11 TEID")
	enodebTEID := flag.Uint("enodeb-teid", 0x7b000001, "synthetic eNodeB S1-U TEID")
	socketBufferBytes := flag.Int("socket-buffer-bytes", 16<<20, "UDP socket buffer request")
	jsonOutput := flag.Bool("json", false, "emit machine-readable JSON")
	flag.Parse()
	if *mmeTEID == 0 || uint64(*mmeTEID) > uint64(^uint32(0)) ||
		*enodebTEID == 0 || uint64(*enodebTEID) > uint64(^uint32(0)) {
		fmt.Fprintln(os.Stderr, "mme-teid and enodeb-teid must be between 1 and 4294967295")
		os.Exit(2)
	}

	parse := func(value, name string) netip.AddrPort {
		address, err := netip.ParseAddrPort(value)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
			os.Exit(2)
		}
		return address
	}
	transport := gtptransport.DefaultConfig()
	transport.RetransmitTimeout = 500 * time.Millisecond
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result, err := epc.RunServiceCUPS(ctx, epc.ServiceCUPSConfig{
		MMEControl: parse(*mme, "mme"), SGWS11: parse(*sgw, "sgw-s11"),
		ENBUser: parse(*enodeb, "enodeb-user"), ExternalUser: parse(*external, "external-user"),
		IMSI: *imsi, APN: *apn, EBI: 5, Timeout: *timeout,
		Transport: transport, SocketBufferBytes: *socketBufferBytes,
		HoldAfterModify: *holdAfterModify, HoldAfterData: *holdAfterData,
		ThroughputDuration: *throughputDuration, ThroughputDirection: *direction,
		PayloadSize: *payloadSize, TargetPacketsPerSecond: *targetPPS, PacketBatchSize: *packetBatchSize,
		MMEControlTEID: uint32(*mmeTEID), ENodeBTEID: uint32(*enodebTEID),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "running-service CUPS validation failed:", err)
		os.Exit(1)
	}
	if *jsonOutput {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		_ = encoder.Encode(result)
		return
	}
	fmt.Println("RUNNING FOUR-COMPONENT CUPS: PASS")
	fmt.Printf("APN %s | UE %s | subscriber %s\n", result.APN, result.UEIPv4, result.Subscriber)
	fmt.Printf("Control latency: Create %.3f ms | Modify %.3f ms | Delete %.3f ms\n",
		result.CreateSessionMilliseconds, result.ModifyBearerMilliseconds, result.DeleteSessionMilliseconds)
	fmt.Printf("User-plane latency: Uplink %.3f ms | Downlink %.3f ms\n",
		result.UplinkMilliseconds, result.DownlinkMilliseconds)
	if result.UplinkThroughput.DurationSeconds > 0 {
		fmt.Printf("Uplink load: %.3f Mbps | %.6f%% loss | %.3f kpps | %d receiver socket drops\n",
			result.UplinkThroughput.Mbps, result.UplinkThroughput.LossPercent,
			result.UplinkThroughput.PacketsPerSecond/1_000, result.UplinkThroughput.ReceiverSocketDroppedPackets)
	}
	if result.DownlinkThroughput.DurationSeconds > 0 {
		fmt.Printf("Downlink load: %.3f Mbps | %.6f%% loss | %.3f kpps | %d receiver socket drops\n",
			result.DownlinkThroughput.Mbps, result.DownlinkThroughput.LossPercent,
			result.DownlinkThroughput.PacketsPerSecond/1_000, result.DownlinkThroughput.ReceiverSocketDroppedPackets)
	}
	fmt.Printf("Bidirectional packet path and detach: PASS | Total %.3f ms\n", result.ElapsedMilliseconds)
}
