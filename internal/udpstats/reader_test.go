package udpstats

import (
	"net"
	"testing"
	"time"
)

func TestReaderOverflowDeltas(t *testing.T) {
	reader := &Reader{}
	for _, test := range []struct {
		cumulative uint32
		want       uint64
	}{
		{cumulative: 7, want: 7},
		{cumulative: 7, want: 0},
		{cumulative: 12, want: 5},
		{cumulative: ^uint32(0) - 1, want: uint64(^uint32(0) - 13)},
		{cumulative: 3, want: 5},
	} {
		if got := reader.observe(test.cumulative); got != test.want {
			t.Fatalf("observe(%d) = %d, want %d", test.cumulative, got, test.want)
		}
	}
}

func TestNewReaderRejectsNilConnection(t *testing.T) {
	if _, err := NewReader(nil); err == nil {
		t.Fatal("NewReader(nil) succeeded")
	}
}

func TestReaderBatchReceivesUDPDatagrams(t *testing.T) {
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	reader, err := NewReader(receiver)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := reader.NewBatch(4, 128)
	if err != nil {
		t.Fatal(err)
	}
	sender, err := net.DialUDP("udp4", nil, receiver.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	if _, err := sender.Write([]byte("batched-gtpu")); err != nil {
		t.Fatal(err)
	}
	if err := receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	n, dropped, err := reader.ReadBatch(batch)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || dropped != 0 || string(batch.Datagrams[0].Buffer[:batch.Datagrams[0].N]) != "batched-gtpu" || !batch.Datagrams[0].Peer.Addr().IsLoopback() {
		t.Fatalf("unexpected batch: n=%d dropped=%d datagram=%#v", n, dropped, batch.Datagrams[0])
	}
}

func TestReaderBatchSendsUDPDatagrams(t *testing.T) {
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	writer, err := NewReader(sender)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := NewSendBatch(4)
	if err != nil {
		t.Fatal(err)
	}
	peer := receiver.LocalAddr().(*net.UDPAddr).AddrPort()
	batch.Append([]byte("one"), peer)
	batch.Append([]byte("two"), peer)
	if sent, err := writer.WriteBatch(batch); err != nil || sent != 2 {
		t.Fatalf("WriteBatch sent=%d err=%v", sent, err)
	}
	if err := receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 16)
	for _, want := range []string{"one", "two"} {
		n, _, err := receiver.ReadFromUDP(buffer)
		if err != nil || string(buffer[:n]) != want {
			t.Fatalf("received %q, err=%v; want %q", buffer[:n], err, want)
		}
	}
}
