package transport

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lodestarnetworks/cups/pkg/pfcp"
)

func TestRequestResponseAndDuplicateCache(t *testing.T) {
	config := DefaultConfig()
	config.RetransmitTimeout = 50 * time.Millisecond
	var handled atomic.Uint64
	server, err := Listen(netip.MustParseAddrPort("127.78.0.2:0"), func(_ context.Context, _ netip.AddrPort, request pfcp.Message) (*pfcp.Message, error) {
		handled.Add(1)
		return &pfcp.Message{
			Header: pfcp.Header{Version: pfcp.Version, MessageType: pfcp.MessageHeartbeatResponse},
			IEs:    []pfcp.IE{pfcp.NewCauseIE(pfcp.CauseRequestAccepted)},
		}, nil
	}, config)
	if err != nil {
		t.Fatal(err)
	}
	client, err := Listen(netip.MustParseAddrPort("127.78.0.3:0"), nil, config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverDone := make(chan error, 1)
	clientDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(ctx) }()
	go func() { clientDone <- client.Serve(ctx) }()

	response, err := client.Do(context.Background(), server.LocalAddr(), pfcp.Message{
		Header: pfcp.Header{Version: pfcp.Version, MessageType: pfcp.MessageHeartbeatRequest},
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.Header.MessageType != pfcp.MessageHeartbeatResponse || handled.Load() != 1 {
		t.Fatalf("response=%#v handled=%d", response, handled.Load())
	}

	cancel()
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if err := <-clientDone; err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentDuplicateIsCoalesced(t *testing.T) {
	config := DefaultConfig()
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	server, err := Listen(netip.MustParseAddrPort("127.78.0.4:0"), func(_ context.Context, _ netip.AddrPort, _ pfcp.Message) (*pfcp.Message, error) {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-release
		return &pfcp.Message{Header: pfcp.Header{Version: pfcp.Version, MessageType: pfcp.MessageHeartbeatResponse}}, nil
	}, config)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go server.Serve(ctx)

	client, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.78.0.5:0")))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	request := pfcp.Message{Header: pfcp.Header{Version: pfcp.Version, MessageType: pfcp.MessageHeartbeatRequest, SequenceNumber: 77}}
	wire, err := request.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.WriteToUDPAddrPort(wire, server.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("handler did not start")
	}
	if _, err := client.WriteToUDPAddrPort(wire, server.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for server.Counters().CacheHits == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	close(release)
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.ReadFromUDP(make([]byte, 2048)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.ReadFromUDP(make([]byte, 2048)); err != nil {
		t.Fatalf("in-flight duplicate did not receive a replayed response: %v", err)
	}
	counters := server.Counters()
	if calls.Load() != 1 || counters.CacheHits != 1 || counters.InflightDuplicates != 1 || counters.InflightReplays != 1 {
		t.Fatalf("handler calls=%d counters=%+v", calls.Load(), counters)
	}
}

func TestTransactionTimeout(t *testing.T) {
	config := DefaultConfig()
	config.RetransmitTimeout = 5 * time.Millisecond
	config.MaxRetransmits = 1
	client, err := Listen(netip.MustParseAddrPort("127.78.1.2:0"), nil, config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Serve(ctx) }()
	_, err = client.Do(context.Background(), netip.MustParseAddrPort("127.78.1.99:8805"), pfcp.Message{
		Header: pfcp.Header{Version: pfcp.Version, MessageType: pfcp.MessageHeartbeatRequest},
	})
	if err != ErrTimeout {
		t.Fatalf("error = %v, want ErrTimeout", err)
	}
	counters := client.Counters()
	if counters.Retransmitted != 1 || counters.TimedOut != 1 {
		t.Fatalf("unexpected counters: %#v", counters)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
