package rules

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestWALRoundTripUpdateAndDelete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pgwu.wal")
	log, recovered, err := OpenWAL(path, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(recovered) != 0 {
		t.Fatalf("new WAL recovered %+v", recovered)
	}
	first := testSession(1)
	first.Revision = 1
	first.ControlPeer = netip.MustParseAddrPort("10.200.0.1:8805")
	if err := log.Commit(nil, &first); err != nil {
		t.Fatal(err)
	}
	second := first
	second.Revision = 2
	second.Remote.TEID++
	if err := log.Commit(&first, &second); err != nil {
		t.Fatal(err)
	}
	third := testSession(2)
	third.Revision = 1
	third.ControlPeer = first.ControlPeer
	if err := log.Commit(nil, &third); err != nil {
		t.Fatal(err)
	}
	if err := log.Commit(&third, nil); err != nil {
		t.Fatal(err)
	}
	if stats := log.Stats(); stats.Records != 4 || stats.Bytes <= walHeaderBytes {
		t.Fatalf("WAL stats = %+v", stats)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, recovered, err := OpenWAL(path, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if len(recovered) != 1 || !reflect.DeepEqual(recovered[0], second) {
		t.Fatalf("recovered sessions = %+v, want %+v", recovered, second)
	}
}

func TestWALReadsVersionOneAndAppendsVersionTwoDelete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pgwu-v1.wal")
	session := testSession(7)
	session.Revision = 1
	payload := make([]byte, walPayloadBytesV1)
	payload[0] = walOperationUpsert
	payload[1] = walFormatVersionV1
	binary.BigEndian.PutUint64(payload[2:10], session.CPSEID)
	binary.BigEndian.PutUint64(payload[10:18], session.UPSEID)
	binary.BigEndian.PutUint64(payload[18:26], session.Revision)
	ue, local, remote := session.UEIPv4.As4(), session.Local.IP.As4(), session.Remote.IP.As4()
	copy(payload[26:30], ue[:])
	binary.BigEndian.PutUint32(payload[30:34], session.Local.TEID)
	copy(payload[34:38], local[:])
	binary.BigEndian.PutUint32(payload[38:42], session.Remote.TEID)
	copy(payload[42:46], remote[:])
	payload[46] = 3
	record := make([]byte, walRecordHeaderBytes+len(payload))
	binary.BigEndian.PutUint32(record[0:4], uint32(len(payload)))
	binary.BigEndian.PutUint32(record[4:8], crc32.Checksum(payload, walCRC))
	copy(record[8:], payload)
	contents := append([]byte(walMagic), record...)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	log, recovered, err := OpenWAL(path, 1<<20)
	if err != nil || len(recovered) != 1 || !reflect.DeepEqual(recovered[0], session) {
		t.Fatalf("v1 recovery sessions=%#v err=%v", recovered, err)
	}
	store := NewStoreWithParticipants(2, nil, log)
	if err := store.Restore(recovered); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(session.UPSEID, session.Revision); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, recovered, err := OpenWAL(path, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if len(recovered) != 0 || reopened.Stats().Records != 2 {
		t.Fatalf("post-delete recovery=%#v stats=%#v", recovered, reopened.Stats())
	}
}

func TestWALRecoversPartialTailAndRejectsChecksumCorruption(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "tail.wal")
	log, _, err := OpenWAL(path, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	session := testSession(1)
	session.Revision = 1
	if err := log.Commit(nil, &session); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte{0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	recoveredLog, recovered, err := OpenWAL(path, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if !recoveredLog.Stats().RecoveredTail || len(recovered) != 1 {
		t.Fatalf("tail recovery stats=%+v sessions=%+v", recoveredLog.Stats(), recovered)
	}
	if err := recoveredLog.Close(); err != nil {
		t.Fatal(err)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	contents[len(contents)-1] ^= 0xff
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenWAL(path, 1<<20); !errors.Is(err, ErrWALCorrupt) {
		t.Fatalf("checksum error = %v", err)
	}
}

func TestWALExclusiveLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "locked.wal")
	first, _, err := OpenWAL(path, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, _, err := OpenWAL(path, 1<<20); !errors.Is(err, ErrWALLocked) {
		t.Fatalf("second open error = %v", err)
	}
}

func TestWALCapacity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bounded.wal")
	max := int64(walHeaderBytes + walRecordHeaderBytes + walPayloadBytes)
	log, _, err := OpenWAL(path, max)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	session := testSession(1)
	session.Revision = 1
	if err := log.Commit(nil, &session); err != nil {
		t.Fatal(err)
	}
	second := testSession(2)
	second.Revision = 1
	if err := log.Commit(nil, &second); !errors.Is(err, ErrWALCapacity) {
		t.Fatalf("capacity error = %v", err)
	}
}

func TestNilWALPersisterIsDisabled(t *testing.T) {
	var log *WAL
	store := NewStoreWithParticipants(1, nil, log)
	if _, err := store.Create(testSession(1)); err != nil {
		t.Fatalf("create through typed-nil WAL: %v", err)
	}
}

func TestWALVersionThreeRoundTripsDedicatedBearers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pgwu-dedicated.wal")
	log, _, err := OpenWAL(path, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	session := testSession(1)
	session.Revision = 1
	session.ControlPeer = netip.MustParseAddrPort("10.200.0.1:8805")
	session.DedicatedBearers = []Bearer{testDedicatedBearer(1, 100), testDedicatedBearer(2, 200)}
	if err := log.Commit(nil, &session); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := contents[walHeaderBytes+walRecordHeaderBytes+1]; got != walFormatVersionV3 {
		t.Fatalf("record version = %d, want %d", got, walFormatVersionV3)
	}

	reopened, recovered, err := OpenWAL(path, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	canonicalize(&session)
	if len(recovered) != 1 || !reflect.DeepEqual(recovered[0], session) {
		t.Fatalf("recovered sessions = %#v, want %#v", recovered, session)
	}
}

func TestWALVersionThreeRejectsUnknownAndInvalidBearerState(t *testing.T) {
	session := testSession(1)
	session.Revision = 1
	session.DedicatedBearers = []Bearer{testDedicatedBearer(1, 100)}
	canonicalize(&session)
	payload, err := encodeWALPayload(walOperationUpsert, session)
	if err != nil {
		t.Fatal(err)
	}
	unknown := append([]byte(nil), payload[:walPayloadBytesV2]...)
	extension := payload[walPayloadBytesV2:]
	unknown = append(unknown, extension[:len(extension)-1]...)
	unknown = append(unknown, []byte(`,"unknown":true}`)...)
	if _, _, err := decodeWALPayload(unknown); err == nil {
		t.Fatal("v3 decoder accepted an unknown field")
	}

	var decoded walV3Extension
	if err := json.Unmarshal(extension, &decoded); err != nil {
		t.Fatal(err)
	}
	decoded.DedicatedBearers[0].Filters[0].Filter.LocalPortLow = 6000
	invalidExtension, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	invalid := append(append([]byte(nil), payload[:walPayloadBytesV2]...), invalidExtension...)
	if _, _, err := decodeWALPayload(invalid); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("invalid v3 bearer error = %v", err)
	}
}
