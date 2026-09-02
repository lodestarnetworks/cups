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
	mme := flag.String("mme", "10.254.10.2:2123", "isolated-netns MME GTPv2-C address")
	sgw := flag.String("sgw-s11", "10.254.10.1:2123", "SGW-C S11 address")
	pgwControl := flag.String("pgw-control", "10.254.20.2:2123", "isolated-netns PGW GTPv2-C address")
	enodeb := flag.String("enodeb-user", "10.254.40.2:2152", "isolated-netns eNodeB GTP-U address")
	pgwUser := flag.String("pgw-user", "10.254.50.2:2152", "isolated-netns PGW GTP-U address")
	imsi := flag.String("imsi", "001010123456789", "synthetic IMSI")
	apn := flag.String("apn", "internet", "APN")
	additionalAPN := flag.String("additional-apn", "ims", "second PDN APN sharing the S11 context; empty disables")
	additionalEBI := flag.Uint("additional-ebi", 6, "second PDN default bearer EBI")
	timeout := flag.Duration("timeout", 5*time.Second, "per-procedure timeout")
	latencySamples := flag.Int("latency-samples", 100, "one-way samples per direction")
	throughputDuration := flag.Duration("throughput-duration", time.Second, "throughput test duration per direction")
	payloadSize := flag.Int("payload-size", 1200, "inner user-packet bytes")
	targetPPS := flag.Int("target-pps", 10_000, "offered packet rate per direction; zero sends as fast as possible")
	socketBufferBytes := flag.Int("socket-buffer-bytes", 16<<20, "UDP socket buffer request for the synthetic peers")
	expectBufferedIdle := flag.Bool("expect-buffered-idle", false, "verify that the idle downlink packet is delivered after bearer resume")
	jsonOutput := flag.Bool("json", false, "emit machine-readable JSON instead of the human summary")
	flag.Parse()
	if *additionalEBI > 255 {
		fmt.Fprintln(os.Stderr, "additional-ebi must fit in one octet")
		os.Exit(2)
	}
	parse := func(value, name string) netip.AddrPort {
		addr, err := netip.ParseAddrPort(value)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
			os.Exit(2)
		}
		return addr
	}
	transport := gtptransport.DefaultConfig()
	transport.RetransmitTimeout = 500 * time.Millisecond
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result, err := epc.Run(ctx, epc.Config{
		MMEControl: parse(*mme, "mme"), SGWS11: parse(*sgw, "sgw-s11"),
		PGWControl: parse(*pgwControl, "pgw-control"), ENBUser: parse(*enodeb, "enodeb-user"),
		PGWUser: parse(*pgwUser, "pgw-user"), IMSI: *imsi, APN: *apn,
		EBI: 5, AdditionalAPN: *additionalAPN, AdditionalEBI: uint8(*additionalEBI),
		Timeout: *timeout, Transport: transport,
		LatencySamples: *latencySamples, ThroughputDuration: *throughputDuration,
		PayloadSize: *payloadSize, TargetPacketsPerSecond: *targetPPS,
		SocketBufferBytes: *socketBufferBytes, ExpectBufferedIdle: *expectBufferedIdle,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "SGW end-to-end validation failed:", err)
		os.Exit(1)
	}
	if *jsonOutput {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		_ = encoder.Encode(result)
		return
	}
	fmt.Println("SGW LTE END-TO-END: PASS")
	fmt.Printf("Scope: %s\n", result.MeasurementScope)
	fmt.Printf("Control latency: Create %.3f ms | Modify %.3f ms | Release %.3f ms | Resume %.3f ms | Delete %.3f ms\n",
		result.ControlLatency.CreateSessionMilliseconds, result.ControlLatency.ModifyBearerMilliseconds,
		result.ControlLatency.ReleaseAccessMilliseconds, result.ControlLatency.ResumeBearerMilliseconds,
		result.ControlLatency.DeleteSessionMilliseconds)
	if result.AdditionalPDN {
		fmt.Printf("Shared-S11 PDN: %s/EBI %d PASS | Create %.3f ms | Modify %.3f ms | Resume %.3f ms | Delete %.3f ms\n",
			result.AdditionalAPN, result.AdditionalEBI,
			result.ControlLatency.AdditionalCreateSessionMilliseconds,
			result.ControlLatency.AdditionalModifyBearerMilliseconds,
			result.ControlLatency.AdditionalResumeMilliseconds,
			result.ControlLatency.AdditionalDeleteSessionMilliseconds)
	}
	fmt.Printf("Uplink latency:   avg %.3f ms | p50 %.3f ms | p95 %.3f ms | p99 %.3f ms\n",
		result.UplinkLatency.AverageMilliseconds, result.UplinkLatency.P50Milliseconds,
		result.UplinkLatency.P95Milliseconds, result.UplinkLatency.P99Milliseconds)
	fmt.Printf("Downlink latency: avg %.3f ms | p50 %.3f ms | p95 %.3f ms | p99 %.3f ms\n",
		result.DownlinkLatency.AverageMilliseconds, result.DownlinkLatency.P50Milliseconds,
		result.DownlinkLatency.P95Milliseconds, result.DownlinkLatency.P99Milliseconds)
	fmt.Printf("Uplink throughput:   %.2f Mbps | %.2f%% loss | %.2f kpps\n",
		result.UplinkThroughput.Mbps, result.UplinkThroughput.LossPercent, result.UplinkThroughput.PacketsPerSecond/1_000)
	fmt.Printf("Downlink throughput: %.2f Mbps | %.2f%% loss | %.2f kpps\n",
		result.DownlinkThroughput.Mbps, result.DownlinkThroughput.LossPercent, result.DownlinkThroughput.PacketsPerSecond/1_000)
	fmt.Printf("Idle downlink blocked: %t | DDN paging trigger: %t | Buffered resume: %t | Detach: complete | Total %.1f ms\n",
		result.IdleDropVerified, result.DDNVerified, result.BufferedIdleVerified, result.ElapsedMilliseconds)
}
