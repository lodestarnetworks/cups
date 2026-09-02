package usagereport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/lodestarnetworks/cups/internal/controlstate"
)

var (
	ErrSequenceGap      = errors.New("PFCP usage report sequence gap")
	ErrSequenceConflict = errors.New("PFCP usage report sequence conflict")
)

type LedgerConfig struct {
	Path     string
	Identity []byte
	MaxBytes int64
}

type LedgerStats struct {
	Durable           bool
	ActiveCheckpoints uint64
	ReportsAccepted   uint64
	ReportsDuplicate  uint64
	SequenceGaps      uint64
	SequenceConflicts uint64
	UplinkPackets     uint64
	DownlinkPackets   uint64
	UplinkBytes       uint64
	DownlinkBytes     uint64
	WALBytes          int64
	WALRecords        uint64
	WALCompactions    uint64
	WALRecoveredTail  bool
}

type AcceptResult struct {
	Accepted  int
	Duplicate int
}

type ledgerKey struct {
	RecoveryUnix int64
	CPSEID       uint64
	URRID        uint32
}

type checkpoint struct {
	Sequence uint32
	Digest   [sha256.Size]byte
}

type ledgerTotals struct {
	ReportsAccepted uint64 `json:"reports_accepted"`
	UplinkPackets   uint64 `json:"uplink_packets"`
	DownlinkPackets uint64 `json:"downlink_packets"`
	UplinkBytes     uint64 `json:"uplink_bytes"`
	DownlinkBytes   uint64 `json:"downlink_bytes"`
}

type ledgerRecord struct {
	Version      uint8         `json:"version"`
	Kind         string        `json:"kind"`
	RecoveryUnix int64         `json:"recovery_unix,omitempty"`
	CPSEID       uint64        `json:"cp_seid,omitempty"`
	URRID        uint32        `json:"urr_id,omitempty"`
	Sequence     uint32        `json:"sequence,omitempty"`
	Digest       string        `json:"digest,omitempty"`
	Reports      []Report      `json:"reports,omitempty"`
	Totals       *ledgerTotals `json:"totals,omitempty"`
}

type Ledger struct {
	mu          sync.Mutex
	journal     *controlstate.Journal
	checkpoints map[ledgerKey]checkpoint
	totals      ledgerTotals
	duplicates  uint64
	gaps        uint64
	conflicts   uint64
	closed      bool
}

func OpenLedger(config LedgerConfig) (*Ledger, error) {
	ledger := &Ledger{checkpoints: make(map[ledgerKey]checkpoint)}
	if config.Path == "" {
		return ledger, nil
	}
	journal, err := controlstate.OpenReplay(controlstate.Config{
		Path: config.Path, Magic: "LSURPT01", Identity: config.Identity,
		MaxBytes: config.MaxBytes, MaxRecordBytes: 8 << 20,
	}, func(index uint64, payload []byte) error {
		if err := ledger.replay(payload); err != nil {
			return fmt.Errorf("usage ledger record %d: %w", index, err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	ledger.journal = journal
	if err := journal.Start(); err != nil {
		_ = journal.Close()
		return nil, err
	}
	return ledger, nil
}

func (l *Ledger) Accept(recovery time.Time, reports []Report) (AcceptResult, error) {
	if l == nil {
		return AcceptResult{}, errors.New("nil PFCP usage ledger")
	}
	if recovery.IsZero() || len(reports) == 0 {
		return AcceptResult{}, errors.New("PFCP usage ledger requires a recovery epoch and at least one report")
	}
	recoveryUnix := recovery.UTC().Unix()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return AcceptResult{}, errors.New("PFCP usage ledger is closed")
	}

	staged := make(map[ledgerKey]checkpoint)
	newReports := make([]Report, 0, len(reports))
	result := AcceptResult{}
	for _, report := range reports {
		if err := report.Validate(); err != nil {
			return AcceptResult{}, err
		}
		key := ledgerKey{RecoveryUnix: recoveryUnix, CPSEID: report.CPSEID, URRID: report.URRID}
		current, exists := staged[key]
		if !exists {
			current, exists = l.checkpoints[key]
		}
		digest, err := reportDigest(report)
		if err != nil {
			return AcceptResult{}, err
		}
		if !exists {
			if report.Sequence != 0 {
				l.gaps++
				return AcceptResult{}, fmt.Errorf("%w: CP-SEID %d URR %d starts at %d", ErrSequenceGap, report.CPSEID, report.URRID, report.Sequence)
			}
		} else {
			if report.Sequence == current.Sequence {
				if digest != current.Digest {
					l.conflicts++
					return AcceptResult{}, fmt.Errorf("%w: CP-SEID %d URR %d sequence %d", ErrSequenceConflict, report.CPSEID, report.URRID, report.Sequence)
				}
				result.Duplicate++
				continue
			}
			if report.Sequence != current.Sequence+1 {
				l.gaps++
				return AcceptResult{}, fmt.Errorf("%w: CP-SEID %d URR %d got %d after %d", ErrSequenceGap, report.CPSEID, report.URRID, report.Sequence, current.Sequence)
			}
		}
		staged[key] = checkpoint{Sequence: report.Sequence, Digest: digest}
		newReports = append(newReports, report)
		result.Accepted++
	}
	if len(newReports) == 0 {
		l.duplicates = saturatingAdd(l.duplicates, uint64(result.Duplicate))
		return result, nil
	}
	record := ledgerRecord{Version: 1, Kind: "accept", RecoveryUnix: recoveryUnix, Reports: newReports}
	wire, err := marshalLedgerRecord(record)
	if err != nil {
		return AcceptResult{}, err
	}
	if err := l.compactIfNeeded(len(wire)); err != nil {
		return AcceptResult{}, err
	}
	if l.journal != nil {
		if err := l.journal.Append(wire); err != nil {
			return AcceptResult{}, err
		}
	}
	for key, value := range staged {
		l.checkpoints[key] = value
	}
	for _, report := range newReports {
		l.addTotals(report)
	}
	l.duplicates = saturatingAdd(l.duplicates, uint64(result.Duplicate))
	return result, nil
}

// RemoveSession bounds sequence-checkpoint state after the authoritative
// control plane has deleted a PFCP session. Cumulative telemetry is retained.
func (l *Ledger) RemoveSession(cpSEID uint64) error {
	if l == nil || cpSEID == 0 {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return errors.New("PFCP usage ledger is closed")
	}
	found := false
	for key := range l.checkpoints {
		if key.CPSEID == cpSEID {
			found = true
			break
		}
	}
	if !found {
		return nil
	}
	record := ledgerRecord{Version: 1, Kind: "delete", CPSEID: cpSEID}
	wire, err := marshalLedgerRecord(record)
	if err != nil {
		return err
	}
	if err := l.compactIfNeeded(len(wire)); err != nil {
		return err
	}
	if l.journal != nil {
		if err := l.journal.Append(wire); err != nil {
			return err
		}
	}
	for key := range l.checkpoints {
		if key.CPSEID == cpSEID {
			delete(l.checkpoints, key)
		}
	}
	return nil
}

func (l *Ledger) Stats() LedgerStats {
	if l == nil {
		return LedgerStats{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	stats := LedgerStats{
		Durable: l.journal != nil, ActiveCheckpoints: uint64(len(l.checkpoints)),
		ReportsAccepted: l.totals.ReportsAccepted, ReportsDuplicate: l.duplicates,
		SequenceGaps: l.gaps, SequenceConflicts: l.conflicts,
		UplinkPackets: l.totals.UplinkPackets, DownlinkPackets: l.totals.DownlinkPackets,
		UplinkBytes: l.totals.UplinkBytes, DownlinkBytes: l.totals.DownlinkBytes,
	}
	if l.journal != nil {
		journal := l.journal.Stats()
		stats.WALBytes, stats.WALRecords = journal.Bytes, journal.DataRecords
		stats.WALCompactions, stats.WALRecoveredTail = journal.Compactions, journal.RecoveredTail
	}
	return stats
}

func (l *Ledger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	if l.journal != nil {
		return l.journal.Close()
	}
	return nil
}

func (l *Ledger) replay(payload []byte) error {
	record, err := unmarshalLedgerRecord(payload)
	if err != nil {
		return err
	}
	switch record.Kind {
	case "accept":
		if record.RecoveryUnix == 0 || len(record.Reports) == 0 {
			return errors.New("malformed accepted-report record")
		}
		for _, report := range record.Reports {
			if err := report.Validate(); err != nil {
				return err
			}
			key := ledgerKey{RecoveryUnix: record.RecoveryUnix, CPSEID: report.CPSEID, URRID: report.URRID}
			digest, err := reportDigest(report)
			if err != nil {
				return err
			}
			if current, exists := l.checkpoints[key]; !exists {
				if report.Sequence != 0 {
					return ErrSequenceGap
				}
			} else if report.Sequence != current.Sequence+1 {
				return ErrSequenceGap
			}
			l.checkpoints[key] = checkpoint{Sequence: report.Sequence, Digest: digest}
			l.addTotals(report)
		}
	case "delete":
		if record.CPSEID == 0 {
			return errors.New("malformed usage-ledger delete record")
		}
		for key := range l.checkpoints {
			if key.CPSEID == record.CPSEID {
				delete(l.checkpoints, key)
			}
		}
	case "snapshot-meta":
		if record.Totals == nil || len(l.checkpoints) != 0 || l.totals.ReportsAccepted != 0 {
			return errors.New("malformed usage-ledger snapshot metadata")
		}
		l.totals = *record.Totals
	case "snapshot-state":
		if record.RecoveryUnix == 0 || record.CPSEID == 0 || record.URRID == 0 || len(record.Digest) != sha256.Size*2 {
			return errors.New("malformed usage-ledger snapshot state")
		}
		raw, err := hex.DecodeString(record.Digest)
		if err != nil || len(raw) != sha256.Size {
			return errors.New("malformed usage-ledger snapshot digest")
		}
		key := ledgerKey{RecoveryUnix: record.RecoveryUnix, CPSEID: record.CPSEID, URRID: record.URRID}
		if _, exists := l.checkpoints[key]; exists {
			return errors.New("duplicate usage-ledger snapshot state")
		}
		var digest [sha256.Size]byte
		copy(digest[:], raw)
		l.checkpoints[key] = checkpoint{Sequence: record.Sequence, Digest: digest}
	default:
		return fmt.Errorf("unknown usage-ledger record kind %q", record.Kind)
	}
	return nil
}

func (l *Ledger) compactIfNeeded(nextLength int) error {
	if l.journal == nil {
		return nil
	}
	records, bytesNeeded, err := l.snapshotRecords()
	if err != nil {
		return err
	}
	if !l.journal.NeedsCompaction(bytesNeeded, nextLength) {
		return nil
	}
	return l.journal.Compact(records)
}

func (l *Ledger) snapshotRecords() ([][]byte, int64, error) {
	meta, err := marshalLedgerRecord(ledgerRecord{Version: 1, Kind: "snapshot-meta", Totals: &l.totals})
	if err != nil {
		return nil, 0, err
	}
	records := make([][]byte, 0, 1+len(l.checkpoints))
	records = append(records, meta)
	keys := make([]ledgerKey, 0, len(l.checkpoints))
	for key := range l.checkpoints {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].RecoveryUnix != keys[j].RecoveryUnix {
			return keys[i].RecoveryUnix < keys[j].RecoveryUnix
		}
		if keys[i].CPSEID != keys[j].CPSEID {
			return keys[i].CPSEID < keys[j].CPSEID
		}
		return keys[i].URRID < keys[j].URRID
	})
	bytesNeeded := controlstate.DataFrameBytes(len(meta))
	for _, key := range keys {
		state := l.checkpoints[key]
		wire, err := marshalLedgerRecord(ledgerRecord{
			Version: 1, Kind: "snapshot-state", RecoveryUnix: key.RecoveryUnix,
			CPSEID: key.CPSEID, URRID: key.URRID, Sequence: state.Sequence,
			Digest: hex.EncodeToString(state.Digest[:]),
		})
		if err != nil {
			return nil, 0, err
		}
		records = append(records, wire)
		bytesNeeded += controlstate.DataFrameBytes(len(wire))
	}
	return records, bytesNeeded, nil
}

func (l *Ledger) addTotals(report Report) {
	l.totals.ReportsAccepted = saturatingAdd(l.totals.ReportsAccepted, 1)
	l.totals.UplinkPackets = saturatingAdd(l.totals.UplinkPackets, report.UplinkPackets)
	l.totals.DownlinkPackets = saturatingAdd(l.totals.DownlinkPackets, report.DownlinkPackets)
	l.totals.UplinkBytes = saturatingAdd(l.totals.UplinkBytes, report.UplinkBytes)
	l.totals.DownlinkBytes = saturatingAdd(l.totals.DownlinkBytes, report.DownlinkBytes)
}

func reportDigest(report Report) ([sha256.Size]byte, error) {
	wire, err := json.Marshal(report)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(wire), nil
}

func marshalLedgerRecord(record ledgerRecord) ([]byte, error) {
	return json.Marshal(record)
}

func unmarshalLedgerRecord(payload []byte) (ledgerRecord, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var record ledgerRecord
	if err := decoder.Decode(&record); err != nil {
		return ledgerRecord{}, err
	}
	if record.Version != 1 {
		return ledgerRecord{}, fmt.Errorf("unsupported usage-ledger record version %d", record.Version)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ledgerRecord{}, errors.New("trailing data in usage-ledger record")
	}
	return record, nil
}
