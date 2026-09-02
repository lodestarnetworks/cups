package rules

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/lodestarnetworks/cups/pkg/gtpv2"
)

type recordingApplier struct {
	previous *Session
	next     *Session
	err      error
	calls    int
}

type recordingPersister struct {
	previous *Session
	next     *Session
	err      error
	calls    int
}

type recordingObserver struct {
	reconciled []Session
	deleted    []uint64
}

func (o *recordingObserver) ReconcileSession(current Session) {
	o.reconciled = append(o.reconciled, current)
}
func (o *recordingObserver) DeleteSession(upSEID uint64) { o.deleted = append(o.deleted, upSEID) }

func (p *recordingPersister) Commit(previous, next *Session) error {
	p.calls++
	p.previous, p.next = cloneSessionPointer(previous), cloneSessionPointer(next)
	return p.err
}

func cloneSessionPointer(session *Session) *Session {
	if session == nil {
		return nil
	}
	copy := *session
	return &copy
}

func (a *recordingApplier) Apply(previous, next *Session) error {
	a.calls++
	if previous != nil {
		copy := *previous
		a.previous = &copy
	} else {
		a.previous = nil
	}
	if next != nil {
		copy := *next
		a.next = &copy
	} else {
		a.next = nil
	}
	return a.err
}

func TestStoreIndexesUpdateAndDelete(t *testing.T) {
	store := NewStoreWithLimit(2)
	created, err := store.Create(testSession(1))
	if err != nil {
		t.Fatal(err)
	}
	for name, ok := range map[string]bool{
		"up":       found(store.FindByUPSEID(created.UPSEID)),
		"cp":       found(store.FindByCPSEID(created.CPSEID)),
		"uplink":   found(store.LookupUplink(created.Local.TEID)),
		"downlink": found(store.LookupDownlink(created.UEIPv4)),
	} {
		if !ok {
			t.Fatalf("%s index failed", name)
		}
	}
	updated, err := store.Update(created.UPSEID, created.Revision, func(candidate *Session) error {
		candidate.Remote = Tunnel{TEID: 999, IP: netip.MustParseAddr("10.200.0.99")}
		return nil
	})
	if err != nil || updated.Remote.TEID != 999 {
		t.Fatalf("update = %#v, %v", updated, err)
	}
	if err := store.Delete(updated.UPSEID, updated.Revision); err != nil {
		t.Fatal(err)
	}
	if store.Count() != 0 || found(store.LookupDownlink(updated.UEIPv4)) {
		t.Fatal("deleted session remains indexed")
	}
}

func TestStoreObserverReceivesSnapshotUpdatesAndDelete(t *testing.T) {
	store := NewStoreWithLimit(2)
	created, err := store.Create(testSession(1))
	if err != nil {
		t.Fatal(err)
	}
	observer := &recordingObserver{}
	store.SetObserver(observer)
	updated, err := store.Update(created.UPSEID, created.Revision, func(candidate *Session) error {
		candidate.MaxUplinkBitsPerSecond = 5_000_000
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(updated.UPSEID, updated.Revision); err != nil {
		t.Fatal(err)
	}
	if len(observer.reconciled) != 2 || observer.reconciled[1].Revision != 2 ||
		len(observer.deleted) != 1 || observer.deleted[0] != created.UPSEID {
		t.Fatalf("observer reconciled=%#v deleted=%#v", observer.reconciled, observer.deleted)
	}
}

func TestStoreCommitsOnlyAfterDataplaneApply(t *testing.T) {
	applier := &recordingApplier{err: errors.New("netlink failed")}
	store := NewStoreWithApplier(2, applier)
	if _, err := store.Create(testSession(1)); !errors.Is(err, ErrDataplane) {
		t.Fatalf("create error = %v", err)
	}
	if store.Count() != 0 {
		t.Fatal("failed dataplane create leaked desired state")
	}

	applier.err = nil
	created, err := store.Create(testSession(1))
	if err != nil {
		t.Fatal(err)
	}
	if applier.previous != nil || applier.next == nil || applier.next.UPSEID != created.UPSEID {
		t.Fatalf("unexpected create transition: previous=%+v next=%+v", applier.previous, applier.next)
	}

	applier.err = errors.New("kernel refused update")
	if _, err := store.Update(created.UPSEID, created.Revision, func(candidate *Session) error {
		candidate.Remote.TEID++
		return nil
	}); !errors.Is(err, ErrDataplane) {
		t.Fatalf("update error = %v", err)
	}
	unchanged, ok := store.FindByUPSEID(created.UPSEID)
	if !ok || unchanged.Revision != created.Revision || unchanged.Remote.TEID != created.Remote.TEID {
		t.Fatalf("failed dataplane update changed store: %+v", unchanged)
	}

	if err := store.Delete(created.UPSEID, created.Revision); !errors.Is(err, ErrDataplane) {
		t.Fatalf("delete error = %v", err)
	}
	if store.Count() != 1 {
		t.Fatal("failed dataplane delete removed desired state")
	}
}

func TestStoreRollsBackDataplaneWhenDurableCommitFails(t *testing.T) {
	applier := &recordingApplier{}
	persister := &recordingPersister{err: errors.New("disk full")}
	store := NewStoreWithParticipants(2, applier, persister)
	if _, err := store.Create(testSession(1)); !errors.Is(err, ErrPersistence) {
		t.Fatalf("create error = %v", err)
	}
	if store.Count() != 0 || applier.previous == nil || applier.next != nil {
		t.Fatalf("failed persistence did not roll back dataplane: previous=%+v next=%+v count=%d", applier.previous, applier.next, store.Count())
	}
	if _, err := store.Create(testSession(2)); !errors.Is(err, ErrPoisoned) {
		t.Fatalf("store accepted mutation after uncertain WAL failure: %v", err)
	}
}

func TestStoreRestoresRecoveredIndexes(t *testing.T) {
	store := NewStoreWithLimit(2)
	first := testSession(1)
	first.Revision = 4
	second := testSession(2)
	second.Revision = 7
	if err := store.Restore([]Session{second, first}); err != nil {
		t.Fatal(err)
	}
	if store.Count() != 2 || !found(store.FindByCPSEID(first.CPSEID)) || !found(store.LookupDownlink(second.UEIPv4)) {
		t.Fatalf("recovered indexes are incomplete: %+v", store.Snapshot())
	}
}

func TestStoreCapacityAndConflicts(t *testing.T) {
	store := NewStoreWithLimit(1)
	first, err := store.Create(testSession(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(testSession(1)); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate error = %v", err)
	}
	if _, err := store.Create(testSession(2)); !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity error = %v", err)
	}
	if err := store.Delete(first.UPSEID, first.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(testSession(2)); err != nil {
		t.Fatalf("capacity slot was not reusable: %v", err)
	}
}

func TestReconcilePreservesUPSEIDAndReplacesRules(t *testing.T) {
	store := NewStoreWithLimit(2)
	created, err := store.Create(testSession(1))
	if err != nil {
		t.Fatal(err)
	}
	replay := testSession(1)
	replay.UPSEID = 999999
	replay.Remote = Tunnel{TEID: 777, IP: netip.MustParseAddr("10.200.0.77")}
	reconciled, err := store.Reconcile(created.CPSEID, replay)
	if err != nil {
		t.Fatal(err)
	}
	if reconciled.UPSEID != created.UPSEID || reconciled.Remote.TEID != 777 || reconciled.Revision != created.Revision+1 {
		t.Fatalf("reconciled session = %#v", reconciled)
	}
	if _, ok := store.LookupUplink(reconciled.Local.TEID); !ok {
		t.Fatal("reconciled tunnel was not indexed")
	}
}

func TestReconcileExactReplayDoesNotRewriteDataplaneOrWAL(t *testing.T) {
	applier := &recordingApplier{}
	persister := &recordingPersister{}
	store := NewStoreWithParticipants(2, applier, persister)
	created, err := store.Create(testSession(1))
	if err != nil {
		t.Fatal(err)
	}
	replay := testSession(1)
	replay.UPSEID = 999999
	reconciled, err := store.Reconcile(created.CPSEID, replay)
	if err != nil {
		t.Fatal(err)
	}
	if reconciled.Revision != created.Revision || applier.calls != 1 || persister.calls != 1 {
		t.Fatalf("exact replay revision=%d applier_calls=%d persister_calls=%d", reconciled.Revision, applier.calls, persister.calls)
	}
}

func TestLockFreePacketIndexesObserveWholeSessionRevisions(t *testing.T) {
	store := NewStoreWithLimit(1)
	initial := testSession(1)
	initial.Remote.TEID = 1_001
	created, err := store.Create(initial)
	if err != nil {
		t.Fatal(err)
	}
	var stop atomic.Bool
	var inconsistent atomic.Uint64
	var group sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for !stop.Load() {
				current, ok := store.LookupUplink(created.Local.TEID)
				if ok && uint64(current.Remote.TEID) != 1_000+current.Revision {
					inconsistent.Add(1)
				}
			}
		}()
	}
	current := created
	for update := 0; update < 1_000; update++ {
		current, err = store.Update(current.UPSEID, current.Revision, func(candidate *Session) error {
			candidate.Remote.TEID = uint32(1_000 + candidate.Revision + 1)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	stop.Store(true)
	group.Wait()
	if inconsistent.Load() != 0 {
		t.Fatalf("packet readers observed %d partial revisions", inconsistent.Load())
	}
	if err := store.Delete(current.UPSEID, current.Revision); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.LookupUplink(current.Local.TEID); ok {
		t.Fatal("deleted session remained visible to lock-free lookup")
	}
}

func TestReconcileRejectsPacketIndexIdentityChange(t *testing.T) {
	store := NewStoreWithLimit(1)
	created, err := store.Create(testSession(1))
	if err != nil {
		t.Fatal(err)
	}
	replay := created
	replay.Local.TEID++
	if _, err := store.Reconcile(created.CPSEID, replay); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("identity-changing reconciliation error = %v", err)
	}
	if current, ok := store.LookupUplink(created.Local.TEID); !ok || current.Revision != created.Revision {
		t.Fatalf("original packet index changed: %#v %v", current, ok)
	}
}

func TestStoreClassifiesDedicatedBearerAndDefaultFallback(t *testing.T) {
	store := NewStoreWithLimit(1)
	candidate := testSession(1)
	voice := testDedicatedBearer(1, 100)
	candidate.DedicatedBearers = []Bearer{voice}
	created, err := store.Create(candidate)
	if err != nil {
		t.Fatal(err)
	}

	downlinkVoice := testIPv4TransportPacket(t, 17, "203.0.113.9", created.UEIPv4.String(), 5061, 5060)
	rule, ok := store.LookupDownlinkPacket(created.UEIPv4, downlinkVoice)
	if !ok || rule.Default || rule.QERID != voice.QERID || rule.Remote.TEID != voice.Remote.TEID {
		t.Fatalf("downlink voice rule = %#v, %v", rule, ok)
	}
	downlinkBulk := testIPv4TransportPacket(t, 6, "203.0.113.9", created.UEIPv4.String(), 443, 49152)
	rule, ok = store.LookupDownlinkPacket(created.UEIPv4, downlinkBulk)
	if !ok || !rule.Default || rule.QERID != created.QERID {
		t.Fatalf("downlink default rule = %#v, %v", rule, ok)
	}

	uplinkVoice := testIPv4TransportPacket(t, 17, created.UEIPv4.String(), "203.0.113.9", 5060, 5061)
	rule, ok = store.LookupUplinkPacket(voice.Local.TEID, uplinkVoice)
	if !ok || rule.Default || rule.QERID != voice.QERID {
		t.Fatalf("uplink voice rule = %#v, %v", rule, ok)
	}
	if _, ok := store.LookupUplinkPacket(voice.Local.TEID, downlinkBulk); ok {
		t.Fatal("dedicated uplink TEID accepted a packet outside its TFT")
	}
	if rule, ok := store.LookupUplinkPacket(created.Local.TEID, downlinkBulk); !ok || !rule.Default {
		t.Fatalf("default uplink rule = %#v, %v", rule, ok)
	}
}

func TestStoreDedicatedBearerPrecedenceAndGenerationReplacement(t *testing.T) {
	store := NewStoreWithLimit(1)
	session := testSession(1)
	lowPriority := testDedicatedBearer(1, 200)
	highPriority := testDedicatedBearer(2, 50)
	session.DedicatedBearers = []Bearer{lowPriority, highPriority}
	created, err := store.Create(session)
	if err != nil {
		t.Fatal(err)
	}
	voice := testIPv4TransportPacket(t, 17, "203.0.113.9", created.UEIPv4.String(), 5061, 5060)
	selected, ok := store.LookupDownlinkPacket(created.UEIPv4, voice)
	if !ok || selected.QERID != highPriority.QERID {
		t.Fatalf("precedence selected %#v, %v", selected, ok)
	}
	uplink := testIPv4TransportPacket(t, 17, created.UEIPv4.String(), "203.0.113.9", 5060, 5061)
	stale, ok := store.LookupUplinkPacket(highPriority.Local.TEID, uplink)
	if !ok {
		t.Fatal("initial dedicated bearer was not indexed")
	}

	updated, err := store.Update(created.UPSEID, created.Revision, func(candidate *Session) error {
		candidate.DedicatedBearers = candidate.DedicatedBearers[:1]
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if stale.generation.active.Load() {
		t.Fatal("superseded packet-rule generation remained active")
	}
	if _, ok := store.LookupUplinkPacket(highPriority.Local.TEID, uplink); ok {
		t.Fatal("removed dedicated bearer TEID remained indexed")
	}
	selected, ok = store.LookupDownlinkPacket(updated.UEIPv4, voice)
	if !ok || selected.QERID != lowPriority.QERID {
		t.Fatalf("replacement generation selected %#v, %v", selected, ok)
	}
}

func TestStoreDeepClonesDedicatedBearerRules(t *testing.T) {
	store := NewStoreWithLimit(1)
	candidate := testSession(1)
	candidate.DedicatedBearers = []Bearer{testDedicatedBearer(1, 100)}
	created, err := store.Create(candidate)
	if err != nil {
		t.Fatal(err)
	}
	candidate.DedicatedBearers[0].Filters[0].Filter.LocalPortLow = 1
	created.DedicatedBearers[0].Filters[0].Filter.LocalPortLow = 2
	current, ok := store.FindByUPSEID(created.UPSEID)
	if !ok || current.DedicatedBearers[0].Filters[0].Filter.LocalPortLow != 5060 {
		t.Fatalf("stored packet filter was aliased: %#v, %v", current, ok)
	}
}

func TestStoreRejectsInvalidDedicatedBearerRules(t *testing.T) {
	tests := map[string]func(*Session){
		"duplicate TEID": func(session *Session) {
			session.DedicatedBearers[0].Local.TEID = session.Local.TEID
		},
		"duplicate PDR": func(session *Session) {
			second := testDedicatedBearer(2, 200)
			second.Filters[0].PDRID = session.DedicatedBearers[0].Filters[0].PDRID
			session.DedicatedBearers = append(session.DedicatedBearers, second)
		},
		"descending port range": func(session *Session) {
			session.DedicatedBearers[0].Filters[0].Filter.LocalPortLow = 6000
		},
		"missing downlink": func(session *Session) {
			session.DedicatedBearers[0].Filters = session.DedicatedBearers[0].Filters[:1]
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			session := testSession(1)
			session.DedicatedBearers = []Bearer{testDedicatedBearer(1, 100)}
			mutate(&session)
			if _, err := NewStoreWithLimit(1).Create(session); !errors.Is(err, ErrInvalidSession) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func testSession(seed uint32) Session {
	return Session{
		CPSEID: uint64(100 + seed), UPSEID: uint64(200 + seed),
		UEIPv4:         netip.AddrFrom4([4]byte{10, 90, 0, byte(seed + 1)}),
		Local:          Tunnel{TEID: 300 + seed, IP: netip.MustParseAddr("10.200.0.20")},
		Remote:         Tunnel{TEID: 400 + seed, IP: netip.MustParseAddr("10.200.0.10")},
		UplinkGateOpen: true, DownlinkGateOpen: true,
	}
}

func testDedicatedBearer(seed uint32, precedence uint32) Bearer {
	filter := func(pdrID uint16, direction gtpv2.TFTDirection) FlowFilter {
		return FlowFilter{
			PDRID: pdrID, Precedence: precedence, Direction: direction,
			Filter: gtpv2.IPv4PacketFilter{
				Direction: direction, HasProtocol: true, Protocol: 17,
				HasLocalPort: true, LocalPortLow: 5060, LocalPortHigh: 5060,
			},
		}
	}
	return Bearer{
		Local:          Tunnel{TEID: 1_300 + seed, IP: netip.MustParseAddr("10.200.0.20")},
		Remote:         Tunnel{TEID: 1_400 + seed, IP: netip.MustParseAddr("10.200.0.10")},
		UplinkFARID:    2_000 + seed*2,
		DownlinkFARID:  2_001 + seed*2,
		UplinkGateOpen: true, DownlinkGateOpen: true,
		QERID: 3_000 + seed, URRID: 4_000 + seed,
		MeasureVolume: true, QCI: 9, ARP: 8,
		Filters: []FlowFilter{
			filter(uint16(5_000+seed*2), gtpv2.TFTDirectionUplink),
			filter(uint16(5_001+seed*2), gtpv2.TFTDirectionDownlink),
		},
	}
}

func testIPv4TransportPacket(t *testing.T, protocol uint8, source, destination string, sourcePort, destinationPort uint16) []byte {
	t.Helper()
	packet := make([]byte, 24)
	packet[0], packet[8], packet[9] = 0x45, 64, protocol
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	sourceAddress := netip.MustParseAddr(source).As4()
	destinationAddress := netip.MustParseAddr(destination).As4()
	copy(packet[12:16], sourceAddress[:])
	copy(packet[16:20], destinationAddress[:])
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], destinationPort)
	return packet
}

func found(_ Session, ok bool) bool { return ok }
