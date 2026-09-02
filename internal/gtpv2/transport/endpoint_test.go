package transport

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lodestarnetworks/cups/pkg/gtpv2"
)

func TestTransactionAndDuplicateCache(t *testing.T) {
	config := DefaultConfig()
	config.RetransmitTimeout = 100 * time.Millisecond
	var calls atomic.Int32
	server, err := Listen(netip.MustParseAddrPort("127.0.0.1:0"), func(_ context.Context, _ netip.AddrPort, request gtpv2.Message) (*gtpv2.Message, error) {
		calls.Add(1)
		return &gtpv2.Message{
			Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageCreateSessionResponse, TEID: 101},
			IEs:    []gtpv2.IE{gtpv2.NewCauseIE(gtpv2.CauseRequestAccepted, 0)},
		}, nil
	}, config)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := Listen(netip.MustParseAddrPort("127.0.0.1:0"), nil, config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go server.Serve(ctx)
	go client.Serve(ctx)

	response, err := client.Do(ctx, server.LocalAddr(), gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageCreateSessionRequest},
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.Header.TEID != 101 || calls.Load() != 1 {
		t.Fatalf("response=%#v calls=%d", response.Header, calls.Load())
	}
	if counters := client.Counters(); counters.Received != 1 || counters.Sent != 1 {
		t.Fatalf("client counters=%#v", counters)
	}
}

func TestConcurrentDuplicateIsCoalesced(t *testing.T) {
	config := DefaultConfig()
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	server, err := Listen(netip.MustParseAddrPort("127.0.0.1:0"), func(_ context.Context, _ netip.AddrPort, _ gtpv2.Message) (*gtpv2.Message, error) {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-release
		return &gtpv2.Message{Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageCreateSessionResponse}}, nil
	}, config)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go server.Serve(ctx)

	client, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	request := gtpv2.Message{Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageCreateSessionRequest, SequenceNumber: 77}}
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

func TestTimeoutRetransmits(t *testing.T) {
	config := DefaultConfig()
	config.RetransmitTimeout = 10 * time.Millisecond
	config.MaxRetransmits = 2
	endpoint, err := Listen(netip.MustParseAddrPort("127.0.0.1:0"), nil, config)
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go endpoint.Serve(ctx)
	_, err = endpoint.Do(ctx, netip.MustParseAddrPort("127.0.0.1:65000"), gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, MessageType: gtpv2.MessageEchoRequest},
	})
	if err != ErrTimeout {
		t.Fatalf("error=%v, want ErrTimeout", err)
	}
	if counters := endpoint.Counters(); counters.Retransmitted != 2 || counters.TimedOut != 1 {
		t.Fatalf("counters=%#v", counters)
	}
}
