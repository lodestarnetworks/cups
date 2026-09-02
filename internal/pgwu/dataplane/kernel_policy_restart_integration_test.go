//go:build linux

package dataplane

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lodestarnetworks/cups/internal/kernelgtp"
	"github.com/lodestarnetworks/cups/internal/pgwu/rules"
	"github.com/lodestarnetworks/cups/pkg/gtpu"
)

const (
	kernelPolicyCrashHelperEnvironment = "SGW_NEXT_KERNEL_POLICY_CRASH_HELPER"
	kernelPolicyCrashOwnerEnvironment  = "SGW_NEXT_KERNEL_POLICY_CRASH_OWNER"
	kernelPolicyCrashWALenvironment    = "SGW_NEXT_KERNEL_POLICY_CRASH_WAL"
	kernelPolicyCrashDefaultName       = "SGW_NEXT_KERNEL_POLICY_DEFAULT_NAME"
	kernelPolicyCrashQCI1Name          = "SGW_NEXT_KERNEL_POLICY_QCI1_NAME"
)

func TestKernelPolicyCrashHelper(t *testing.T) {
	if os.Getenv(kernelPolicyCrashHelperEnvironment) != "1" {
		t.Skip("kernel-policy crash helper is started only by its parent integration test")
	}
	forwarder, err := OpenKernel(kernelPolicyRestartConfig(
		os.Getenv(kernelPolicyCrashOwnerEnvironment),
		os.Getenv(kernelPolicyCrashDefaultName),
		os.Getenv(kernelPolicyCrashQCI1Name),
	))
	if err != nil {
		t.Fatal(err)
	}
	log, recovered, err := rules.OpenWAL(os.Getenv(kernelPolicyCrashWALenvironment), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	store := rules.NewStoreWithParticipants(100, forwarder, log)
	if len(recovered) == 0 {
		if _, err := store.Create(kernelPolicyTestSession(
			netip.MustParseAddr("10.254.77.1"), netip.MustParseAddr("10.254.77.4"),
			netip.MustParseAddr("10.254.77.2"), netip.MustParseAddr("10.254.200.7"),
		)); err != nil {
			t.Fatal(err)
		}
	} else if err := store.Restore(recovered); err != nil {
		t.Fatal(err)
	}
	fmt.Println("READY")
	if err := os.Stdout.Sync(); err != nil {
		t.Fatal(err)
	}
	select {}
}

func TestKernelPolicyAbruptRestartRestoresDedicatedBearer(t *testing.T) {
	if os.Getenv("SGW_NEXT_KERNEL_GTP_TEST") != "1" {
		t.Skip("kernel-policy restart test requires a disposable network namespace")
	}
	if os.Geteuid() != 0 {
		t.Fatal("kernel-policy restart test requires root")
	}
	ownerDirectory := t.TempDir()
	walPath := filepath.Join(t.TempDir(), "pgwu.wal")
	suffix := os.Getpid() % 100_000
	defaultName := fmt.Sprintf("lodrd%d", suffix)
	qci1Name := fmt.Sprintf("lodr1%d", suffix)
	command := exec.Command(os.Args[0], "-test.run=^TestKernelPolicyCrashHelper$")
	command.Env = append(os.Environ(),
		kernelPolicyCrashHelperEnvironment+"=1",
		kernelPolicyCrashOwnerEnvironment+"="+ownerDirectory,
		kernelPolicyCrashWALenvironment+"="+walPath,
		kernelPolicyCrashDefaultName+"="+defaultName,
		kernelPolicyCrashQCI1Name+"="+qci1Name,
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
	childRunning := true
	t.Cleanup(func() {
		if childRunning {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	})
	ready := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if strings.TrimSpace(scanner.Text()) == "READY" {
				ready <- nil
				return
			}
		}
		if err := scanner.Err(); err != nil {
			ready <- err
		} else {
			ready <- fmt.Errorf("helper exited before readiness: %s", stderr.String())
		}
	}()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for crash helper: %s", stderr.String())
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("crash helper exited cleanly after SIGKILL")
	}
	childRunning = false

	log, recovered, err := rules.OpenWAL(walPath, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	if len(recovered) != 1 || len(recovered[0].DedicatedBearers) != 1 {
		t.Fatalf("recovered PGW-U state = %#v", recovered)
	}
	forwarder, err := OpenKernel(kernelPolicyRestartConfig(ownerDirectory, defaultName, qci1Name))
	if err != nil {
		t.Fatalf("open PGW-U after abrupt crash: %v (helper stderr: %s)", err, stderr.String())
	}
	defer forwarder.Close()
	recovery := forwarder.RecoveryReport()
	if !recovery.LinkRemoved || !recovery.PeerFilterRemoved {
		t.Fatalf("abrupt restart recovery report = %+v", recovery)
	}
	store := rules.NewStoreWithParticipants(100, forwarder, log)
	if err := store.Restore(recovered); err != nil {
		t.Fatal(err)
	}

	peerOuter := netip.MustParseAddr("10.254.77.2")
	qci1Outer := netip.MustParseAddr("10.254.77.4")
	serviceIP := netip.MustParseAddr("10.254.77.3")
	ueIP := recovered[0].UEIPv4
	peer, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(peerOuter, kernelgtp.GTPUPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	service, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(serviceIP, 5_061)))
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	if _, err := service.WriteToUDPAddrPort([]byte("post-crash-qci1"), netip.AddrPortFrom(ueIP, 5_060)); err != nil {
		t.Fatal(err)
	}
	if err := peer.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 2_048)
	n, source, err := peer.ReadFromUDPAddrPort(buffer)
	if err != nil {
		t.Fatal(err)
	}
	header, _, err := gtpu.Parse(buffer[:n])
	if err != nil {
		t.Fatal(err)
	}
	if source.Addr().Unmap() != qci1Outer || header.TEID != recovered[0].DedicatedBearers[0].Remote.TEID {
		t.Fatalf("post-crash QCI 1 source=%s TEID=%d", source.Addr(), header.TEID)
	}
}

func kernelPolicyRestartConfig(ownerDirectory, defaultName, qci1Name string) KernelConfig {
	return KernelConfig{
		S5: netip.MustParseAddrPort("10.254.77.1:2152"), QCI1S5: netip.MustParseAddrPort("10.254.77.4:2152"),
		AllowedSGWPeers: []netip.Addr{netip.MustParseAddr("10.254.77.2")},
		TunnelName:      defaultName, QCI1TunnelName: qci1Name,
		OwnershipFile: filepath.Join(ownerDirectory, "default.owner"), QCI1OwnershipFile: filepath.Join(ownerDirectory, "qci1.owner"),
		UEPoolPrefix: netip.MustParsePrefix("10.254.200.0/24"), UEGateway: netip.MustParseAddr("10.254.200.1"),
		HashSize: 4_096, MTU: 1_400, SocketBufferBytes: 4 * 1024 * 1024,
		MaxSessions: 100, MaxPolicyFilters: 1_024, QERBurstDuration: 100 * time.Millisecond,
	}
}
