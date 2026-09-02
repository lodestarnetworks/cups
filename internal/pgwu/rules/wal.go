package rules

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	walMagic             = "LSNPWAL1"
	walFormatVersionV1   = 1
	walFormatVersionV2   = 2
	walFormatVersionV3   = 3
	walOperationUpsert   = 1
	walOperationDelete   = 2
	walHeaderBytes       = 8
	walRecordHeaderBytes = 8
	walPayloadBytesV1    = 69
	walPayloadBytesV2    = 86
	walMaxPayloadBytes   = 1 << 20
	DefaultWALMaxBytes   = int64(1 << 30)
)

// Keep the old internal name for tests which construct a legacy v2 record.
const walPayloadBytes = walPayloadBytesV2

var (
	ErrWALCorrupt  = errors.New("pgwu rules WAL is corrupt")
	ErrWALLocked   = errors.New("pgwu rules WAL is locked by another process")
	ErrWALCapacity = errors.New("pgwu rules WAL capacity reached")
	walCRC         = crc32.MakeTable(crc32.Castagnoli)
)

type WALStats struct {
	Bytes         int64
	Records       uint64
	RecoveredTail bool
}

// WAL is a checksummed, fsync-before-acknowledgement transition log. The file
// is mode 0600, cannot be a symlink, and is exclusively locked for its entire
// lifetime. A partial final record is truncated during recovery; a checksum or
// semantic failure anywhere else fails closed.
type WAL struct {
	mu       sync.Mutex
	file     *os.File
	path     string
	maxBytes int64
	stats    WALStats
	failed   error
	closed   bool
}

func OpenWAL(path string, maxBytes int64) (*WAL, []Session, error) {
	path = filepath.Clean(path)
	if path == "." || path == string(filepath.Separator) || !filepath.IsAbs(path) {
		return nil, nil, errors.New("pgwu rules WAL path must be an absolute file path")
	}
	if maxBytes == 0 {
		maxBytes = DefaultWALMaxBytes
	}
	if maxBytes < walHeaderBytes+walRecordHeaderBytes+walPayloadBytesV2 {
		return nil, nil, errors.New("pgwu rules WAL maximum size is too small")
	}
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_APPEND|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open PGW-U state WAL %q: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	closeOnError := func(cause error) (*WAL, []Session, error) {
		_ = file.Close()
		return nil, nil, cause
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return closeOnError(fmt.Errorf("inspect PGW-U state WAL %q: %w", path, err))
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return closeOnError(fmt.Errorf("PGW-U state WAL %q is not a regular file", path))
	}
	if stat.Mode&0o077 != 0 {
		return closeOnError(fmt.Errorf("PGW-U state WAL %q must not grant group or other permissions", path))
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return closeOnError(fmt.Errorf("PGW-U state WAL %q is not owned by the running uid", path))
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return closeOnError(fmt.Errorf("%w: %s", ErrWALLocked, path))
		}
		return closeOnError(fmt.Errorf("lock PGW-U state WAL %q: %w", path, err))
	}
	log := &WAL{file: file, path: path, maxBytes: maxBytes}
	recovered, err := log.replay(stat.Size)
	if err != nil {
		_ = unix.Flock(fd, unix.LOCK_UN)
		return closeOnError(err)
	}
	return log, recovered, nil
}

func (w *WAL) Commit(previous, next *Session) error {
	// A disabled WAL can arrive through the Persister interface as a typed nil.
	// Treat it exactly like an absent persister instead of dereferencing it.
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return errors.New("PGW-U state WAL is closed")
	}
	if w.failed != nil {
		return fmt.Errorf("PGW-U state WAL previously failed: %w", w.failed)
	}
	operation := byte(walOperationUpsert)
	var session Session
	if next != nil {
		session = clone(*next)
	} else if previous != nil {
		operation = walOperationDelete
		session = clone(*previous)
	} else {
		return errors.New("PGW-U state WAL transition is empty")
	}
	canonicalize(&session)
	if session.Revision == 0 {
		return fmt.Errorf("%w: WAL session revision is zero", ErrInvalidSession)
	}
	if err := validate(session); err != nil {
		return err
	}
	payload, err := encodeWALPayload(operation, session)
	if err != nil {
		return err
	}
	record := make([]byte, walRecordHeaderBytes+len(payload))
	binary.BigEndian.PutUint32(record[0:4], uint32(len(payload)))
	binary.BigEndian.PutUint32(record[4:8], crc32.Checksum(payload, walCRC))
	copy(record[8:], payload)
	if w.stats.Bytes+int64(len(record)) > w.maxBytes {
		return ErrWALCapacity
	}
	if err := writeFull(w.file, record); err != nil {
		w.failed = err
		return fmt.Errorf("append PGW-U state WAL: %w", err)
	}
	if err := w.file.Sync(); err != nil {
		w.failed = err
		return fmt.Errorf("sync PGW-U state WAL: %w", err)
	}
	w.stats.Bytes += int64(len(record))
	w.stats.Records++
	return nil
}

func (w *WAL) Stats() WALStats {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.stats
}

func (w *WAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	unlockErr := unix.Flock(int(w.file.Fd()), unix.LOCK_UN)
	return errors.Join(unlockErr, w.file.Close())
}

func (w *WAL) replay(size int64) ([]Session, error) {
	if size > w.maxBytes {
		return nil, fmt.Errorf("%w: WAL size %d exceeds limit %d", ErrWALCapacity, size, w.maxBytes)
	}
	if size == 0 {
		if err := writeFull(w.file, []byte(walMagic)); err != nil {
			return nil, fmt.Errorf("initialize PGW-U state WAL: %w", err)
		}
		if err := w.file.Sync(); err != nil {
			return nil, fmt.Errorf("sync new PGW-U state WAL: %w", err)
		}
		size = walHeaderBytes
	}
	if size < walHeaderBytes {
		return nil, fmt.Errorf("%w: truncated file header", ErrWALCorrupt)
	}
	magic := make([]byte, walHeaderBytes)
	if _, err := w.file.ReadAt(magic, 0); err != nil {
		return nil, fmt.Errorf("read PGW-U state WAL header: %w", err)
	}
	if string(magic) != walMagic {
		return nil, fmt.Errorf("%w: unknown file header", ErrWALCorrupt)
	}

	byUP := make(map[uint64]Session)
	offset := int64(walHeaderBytes)
	var records uint64
	for offset < size {
		if size-offset < walRecordHeaderBytes {
			if err := w.truncateTail(offset); err != nil {
				return nil, err
			}
			size = offset
			break
		}
		header := make([]byte, walRecordHeaderBytes)
		if _, err := w.file.ReadAt(header, offset); err != nil {
			return nil, fmt.Errorf("read PGW-U state WAL record header at %d: %w", offset, err)
		}
		length := int64(binary.BigEndian.Uint32(header[0:4]))
		if length < walPayloadBytesV1 || length > walMaxPayloadBytes {
			return nil, fmt.Errorf("%w: invalid record length %d at %d", ErrWALCorrupt, length, offset)
		}
		if size-offset-walRecordHeaderBytes < length {
			if err := w.truncateTail(offset); err != nil {
				return nil, err
			}
			size = offset
			break
		}
		payload := make([]byte, length)
		if _, err := w.file.ReadAt(payload, offset+walRecordHeaderBytes); err != nil {
			return nil, fmt.Errorf("read PGW-U state WAL record at %d: %w", offset, err)
		}
		if got, want := crc32.Checksum(payload, walCRC), binary.BigEndian.Uint32(header[4:8]); got != want {
			return nil, fmt.Errorf("%w: checksum mismatch at %d", ErrWALCorrupt, offset)
		}
		operation, session, err := decodeWALPayload(payload)
		if err != nil {
			return nil, fmt.Errorf("%w: record at %d: %v", ErrWALCorrupt, offset, err)
		}
		previous, exists := byUP[session.UPSEID]
		switch operation {
		case walOperationUpsert:
			if !exists && session.Revision != 1 {
				return nil, fmt.Errorf("%w: initial revision is %d at %d", ErrWALCorrupt, session.Revision, offset)
			}
			if exists && (session.Revision != previous.Revision+1 || session.CPSEID != previous.CPSEID) {
				return nil, fmt.Errorf("%w: non-monotonic update at %d", ErrWALCorrupt, offset)
			}
			byUP[session.UPSEID] = session
		case walOperationDelete:
			if !exists || !reflect.DeepEqual(session, previous) {
				return nil, fmt.Errorf("%w: delete does not match live session at %d", ErrWALCorrupt, offset)
			}
			delete(byUP, session.UPSEID)
		default:
			return nil, fmt.Errorf("%w: unknown operation %d at %d", ErrWALCorrupt, operation, offset)
		}
		records++
		offset += walRecordHeaderBytes + length
	}
	result := make([]Session, 0, len(byUP))
	for _, session := range byUP {
		result = append(result, session)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].UPSEID < result[j].UPSEID })
	w.stats.Bytes = size
	w.stats.Records = records
	return result, nil
}

func (w *WAL) truncateTail(offset int64) error {
	if err := w.file.Truncate(offset); err != nil {
		return fmt.Errorf("truncate partial PGW-U state WAL tail: %w", err)
	}
	if err := w.file.Sync(); err != nil {
		return fmt.Errorf("sync truncated PGW-U state WAL: %w", err)
	}
	w.stats.RecoveredTail = true
	return nil
}

func encodeWALPayload(operation byte, session Session) ([]byte, error) {
	payload := make([]byte, walPayloadBytesV2)
	payload[0] = operation
	payload[1] = walFormatVersionV2
	binary.BigEndian.PutUint64(payload[2:10], session.CPSEID)
	binary.BigEndian.PutUint64(payload[10:18], session.UPSEID)
	binary.BigEndian.PutUint64(payload[18:26], session.Revision)
	ue := session.UEIPv4.As4()
	local := session.Local.IP.As4()
	remote := session.Remote.IP.As4()
	copy(payload[26:30], ue[:])
	binary.BigEndian.PutUint32(payload[30:34], session.Local.TEID)
	copy(payload[34:38], local[:])
	binary.BigEndian.PutUint32(payload[38:42], session.Remote.TEID)
	copy(payload[42:46], remote[:])
	if session.UplinkGateOpen {
		payload[46] |= 1
	}
	if session.DownlinkGateOpen {
		payload[46] |= 2
	}
	binary.BigEndian.PutUint64(payload[47:55], session.MaxUplinkBitsPerSecond)
	binary.BigEndian.PutUint64(payload[55:63], session.MaxDownlinkBitsPerSecond)
	if session.ControlPeer.IsValid() {
		if !session.ControlPeer.Addr().Is4() || session.ControlPeer.Port() == 0 {
			return nil, fmt.Errorf("%w: invalid WAL control peer", ErrInvalidSession)
		}
		peer := session.ControlPeer.Addr().As4()
		copy(payload[63:67], peer[:])
		binary.BigEndian.PutUint16(payload[67:69], session.ControlPeer.Port())
	}
	binary.BigEndian.PutUint32(payload[69:73], session.QERID)
	binary.BigEndian.PutUint32(payload[73:77], session.URRID)
	if session.MeasureVolume {
		payload[77] |= 1
	}
	if session.MeasureDuration {
		payload[77] |= 2
	}
	binary.BigEndian.PutUint64(payload[78:86], session.UsageReportingThreshold)
	if len(session.DedicatedBearers) == 0 && session.UplinkPDRID == 0 && session.DownlinkPDRID == 0 && session.UplinkFARID == 0 && session.DownlinkFARID == 0 {
		return payload, nil
	}
	payload[1] = walFormatVersionV3
	extension, err := json.Marshal(walV3Extension{
		UplinkPDRID: session.UplinkPDRID, DownlinkPDRID: session.DownlinkPDRID,
		UplinkFARID: session.UplinkFARID, DownlinkFARID: session.DownlinkFARID,
		DedicatedBearers: session.DedicatedBearers,
	})
	if err != nil {
		return nil, fmt.Errorf("encode PGW-U WAL v3 extension: %w", err)
	}
	if len(payload)+len(extension) > walMaxPayloadBytes {
		return nil, fmt.Errorf("%w: encoded PGW-U session is %d bytes", ErrWALCapacity, len(payload)+len(extension))
	}
	payload = append(payload, extension...)
	return payload, nil
}

type walV3Extension struct {
	UplinkPDRID      uint16   `json:"uplink_pdr_id,omitempty"`
	DownlinkPDRID    uint16   `json:"downlink_pdr_id,omitempty"`
	UplinkFARID      uint32   `json:"uplink_far_id,omitempty"`
	DownlinkFARID    uint32   `json:"downlink_far_id,omitempty"`
	DedicatedBearers []Bearer `json:"dedicated_bearers"`
}

func decodeWALPayload(payload []byte) (byte, Session, error) {
	version := byte(0)
	if len(payload) > 1 {
		version = payload[1]
	}
	if (len(payload) != walPayloadBytesV1 || version != walFormatVersionV1) &&
		(len(payload) != walPayloadBytesV2 || version != walFormatVersionV2) &&
		(len(payload) <= walPayloadBytesV2 || len(payload) > walMaxPayloadBytes || version != walFormatVersionV3) {
		return 0, Session{}, errors.New("unsupported WAL payload")
	}
	address := func(raw []byte) netip.Addr {
		var value [4]byte
		copy(value[:], raw)
		return netip.AddrFrom4(value)
	}
	session := Session{
		CPSEID: binary.BigEndian.Uint64(payload[2:10]), UPSEID: binary.BigEndian.Uint64(payload[10:18]),
		Revision: binary.BigEndian.Uint64(payload[18:26]), UEIPv4: address(payload[26:30]),
		Local:          Tunnel{TEID: binary.BigEndian.Uint32(payload[30:34]), IP: address(payload[34:38])},
		Remote:         Tunnel{TEID: binary.BigEndian.Uint32(payload[38:42]), IP: address(payload[42:46])},
		UplinkGateOpen: payload[46]&1 != 0, DownlinkGateOpen: payload[46]&2 != 0,
		MaxUplinkBitsPerSecond: binary.BigEndian.Uint64(payload[47:55]), MaxDownlinkBitsPerSecond: binary.BigEndian.Uint64(payload[55:63]),
	}
	peer := address(payload[63:67])
	peerPort := binary.BigEndian.Uint16(payload[67:69])
	if !peer.IsUnspecified() || peerPort != 0 {
		if peer.IsUnspecified() || peerPort == 0 {
			return 0, Session{}, errors.New("incomplete WAL control peer")
		}
		session.ControlPeer = netip.AddrPortFrom(peer, peerPort)
	}
	if version == walFormatVersionV2 || version == walFormatVersionV3 {
		session.QERID = binary.BigEndian.Uint32(payload[69:73])
		session.URRID = binary.BigEndian.Uint32(payload[73:77])
		session.MeasureVolume = payload[77]&1 != 0
		session.MeasureDuration = payload[77]&2 != 0
		session.UsageReportingThreshold = binary.BigEndian.Uint64(payload[78:86])
	}
	if version == walFormatVersionV3 {
		decoder := json.NewDecoder(bytes.NewReader(payload[walPayloadBytesV2:]))
		decoder.DisallowUnknownFields()
		var extension walV3Extension
		if err := decoder.Decode(&extension); err != nil {
			return 0, Session{}, fmt.Errorf("invalid WAL v3 extension: %w", err)
		}
		if err := requireJSONEOF(decoder); err != nil {
			return 0, Session{}, err
		}
		if len(extension.DedicatedBearers) == 0 && extension.UplinkPDRID == 0 && extension.DownlinkPDRID == 0 && extension.UplinkFARID == 0 && extension.DownlinkFARID == 0 {
			return 0, Session{}, errors.New("WAL v3 extension has no extended rule state")
		}
		session.UplinkPDRID, session.DownlinkPDRID = extension.UplinkPDRID, extension.DownlinkPDRID
		session.UplinkFARID, session.DownlinkFARID = extension.UplinkFARID, extension.DownlinkFARID
		session.DedicatedBearers = extension.DedicatedBearers
	}
	canonicalize(&session)
	if session.Revision == 0 {
		return 0, Session{}, errors.New("zero WAL revision")
	}
	if err := validate(session); err != nil {
		return 0, Session{}, err
	}
	return payload[0], session, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("WAL v3 extension has trailing JSON")
		}
		return fmt.Errorf("invalid WAL v3 trailing data: %w", err)
	}
	return nil
}

func writeFull(file *os.File, data []byte) error {
	for len(data) > 0 {
		written, err := file.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return errors.New("short write")
		}
		data = data[written:]
	}
	return nil
}
