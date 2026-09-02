package session

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"
	"sync"

	"github.com/lodestarnetworks/cups/internal/controlstate"
)

const (
	sgwcWALMagic         = "LSNSGWC1"
	walOperationUpsert   = "upsert"
	walOperationDelete   = "delete"
	walOperationSnapshot = "snapshot"
	DefaultWALMaxBytes   = controlstate.DefaultMaxBytes
)

type WALStats = controlstate.Stats

type WAL struct {
	mu            sync.Mutex
	journal       *controlstate.Journal
	snapshots     map[uint64][]byte
	snapshotBytes int64
}

type walRecord struct {
	Operation string  `json:"operation"`
	Session   Session `json:"session"`
}

func OpenWAL(path string, maxBytes int64, identity []byte, recoverySeed uint8) (*WAL, []Session, error) {
	byID := make(map[uint64]Session)
	snapshotPhase := true
	journal, err := controlstate.OpenReplay(controlstate.Config{
		Path: path, Magic: sgwcWALMagic, Identity: identity,
		MaxBytes: maxBytes, MaxRecordBytes: controlstate.DefaultMaxRecord, RecoverySeed: recoverySeed,
	}, func(index uint64, raw []byte) error {
		record, err := decodeWALRecord(raw)
		if err != nil {
			return fmt.Errorf("%w: SGW-C record %d: %v", controlstate.ErrCorrupt, index, err)
		}
		current, exists := byID[record.Session.ID]
		switch record.Operation {
		case walOperationSnapshot:
			if !snapshotPhase || exists {
				return fmt.Errorf("%w: SGW-C snapshot record is misplaced or duplicated at %d", controlstate.ErrCorrupt, index)
			}
			byID[record.Session.ID] = clone(record.Session)
		case walOperationUpsert:
			snapshotPhase = false
			if !exists && record.Session.Revision != 1 {
				return fmt.Errorf("%w: SGW-C initial revision %d in record %d", controlstate.ErrCorrupt, record.Session.Revision, index)
			}
			if exists && !validWALUpdate(current, record.Session) {
				return fmt.Errorf("%w: SGW-C non-monotonic or identity-changing update in record %d", controlstate.ErrCorrupt, index)
			}
			byID[record.Session.ID] = clone(record.Session)
		case walOperationDelete:
			snapshotPhase = false
			if !exists || !reflect.DeepEqual(current, record.Session) {
				return fmt.Errorf("%w: SGW-C delete does not match live session in record %d", controlstate.ErrCorrupt, index)
			}
			delete(byID, record.Session.ID)
		default:
			return fmt.Errorf("%w: unknown SGW-C operation %q", controlstate.ErrCorrupt, record.Operation)
		}
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("open SGW-C state: %w", err)
	}
	closeOnError := func(cause error) (*WAL, []Session, error) {
		_ = journal.Close()
		return nil, nil, cause
	}
	recovered := make([]Session, 0, len(byID))
	for _, candidate := range byID {
		recovered = append(recovered, candidate)
	}
	sort.Slice(recovered, func(i, j int) bool { return recovered[i].ID < recovered[j].ID })
	if err := validateRecoveredIndexes(recovered); err != nil {
		return closeOnError(fmt.Errorf("%w: recovered SGW-C index validation: %v", controlstate.ErrCorrupt, err))
	}
	snapshots := make(map[uint64][]byte, len(recovered))
	var snapshotBytes int64
	for _, candidate := range recovered {
		encoded, err := encodeWALRecord(walOperationSnapshot, candidate)
		if err != nil {
			return closeOnError(fmt.Errorf("encode recovered SGW-C snapshot: %w", err))
		}
		snapshots[candidate.ID] = encoded
		snapshotBytes += controlstate.DataFrameBytes(len(encoded))
	}
	return &WAL{journal: journal, snapshots: snapshots, snapshotBytes: snapshotBytes}, recovered, nil
}

func validateRecoveredIndexes(recovered []Session) error {
	owners := make(map[string]struct{}, len(recovered))
	s5 := make(map[uint32]struct{}, len(recovered))
	pfcp := make(map[uint64]struct{}, len(recovered))
	type s11Owner struct {
		subscriber string
		mme        FTEID
		local      FTEID
		bearers    uint16
	}
	s11 := make(map[uint32]s11Owner)
	for _, candidate := range recovered {
		owner := ownerKey(candidate.SubscriberKey, candidate.APN)
		if _, exists := owners[owner]; exists {
			return ErrDuplicate
		}
		owners[owner] = struct{}{}
		if _, exists := s5[candidate.S5Control.TEID]; exists {
			return ErrDuplicate
		}
		s5[candidate.S5Control.TEID] = struct{}{}
		if _, exists := pfcp[candidate.PFCPControlSEID]; exists {
			return ErrDuplicate
		}
		pfcp[candidate.PFCPControlSEID] = struct{}{}
		current := s11[candidate.S11Control.TEID]
		if current.subscriber != "" && (current.subscriber != candidate.SubscriberKey || current.mme != candidate.MMEControl || current.local != candidate.S11Control) {
			return ErrDuplicate
		}
		for ebi := range candidate.Bearers {
			bit := uint16(1) << ebi
			if current.bearers&bit != 0 {
				return ErrDuplicate
			}
			current.bearers |= bit
		}
		current.subscriber, current.mme, current.local = candidate.SubscriberKey, candidate.MMEControl, candidate.S11Control
		s11[candidate.S11Control.TEID] = current
	}
	return nil
}

// Start commits a new SGW-C ownership epoch after the caller has validated and
// restored every recovered session and dependent allocator.
func (w *WAL) Start() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.journal.Start(); err != nil {
		return fmt.Errorf("start SGW-C state: %w", err)
	}
	return nil
}

func (w *WAL) Commit(previous, next *Session) error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	record := walRecord{Operation: walOperationUpsert}
	if next != nil {
		record.Session = clone(*next)
	} else if previous != nil {
		record.Operation = walOperationDelete
		record.Session = clone(*previous)
	} else {
		return errors.New("SGW-C state transition is empty")
	}
	if err := validateWALSession(record.Session); err != nil {
		return err
	}
	priorSnapshot, exists := w.snapshots[record.Session.ID]
	if previous == nil {
		if exists || next == nil || next.Revision != 1 {
			return errors.New("SGW-C durable create does not match journal state")
		}
	} else {
		expectedPrevious, err := encodeWALRecord(walOperationSnapshot, *previous)
		if err != nil {
			return fmt.Errorf("encode prior SGW-C state snapshot: %w", err)
		}
		if !exists || !bytes.Equal(priorSnapshot, expectedPrevious) {
			return errors.New("SGW-C durable transition does not match journal state")
		}
		if next != nil && !validWALUpdate(*previous, *next) {
			return errors.New("SGW-C durable update is non-monotonic or changes immutable identity")
		}
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode SGW-C state transition: %w", err)
	}
	var nextSnapshot []byte
	if next != nil {
		nextSnapshot, err = encodeWALRecord(walOperationSnapshot, *next)
		if err != nil {
			return fmt.Errorf("encode SGW-C state snapshot: %w", err)
		}
	}
	if w.journal.NeedsCompaction(w.snapshotBytes, len(encoded)) {
		if err := w.compactLocked(); err != nil {
			return fmt.Errorf("compact SGW-C state before transition: %w", err)
		}
	}
	if err := w.journal.Append(encoded); err != nil {
		return fmt.Errorf("commit SGW-C state transition: %w", err)
	}
	if prior, ok := w.snapshots[record.Session.ID]; ok {
		w.snapshotBytes -= controlstate.DataFrameBytes(len(prior))
	}
	if next == nil {
		delete(w.snapshots, record.Session.ID)
	} else {
		w.snapshots[next.ID] = nextSnapshot
		w.snapshotBytes += controlstate.DataFrameBytes(len(nextSnapshot))
	}
	return nil
}

func (w *WAL) compactLocked() error {
	ids := make([]uint64, 0, len(w.snapshots))
	for id := range w.snapshots {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	records := make([][]byte, 0, len(ids))
	for _, id := range ids {
		records = append(records, w.snapshots[id])
	}
	return w.journal.Compact(records)
}

func encodeWALRecord(operation string, candidate Session) ([]byte, error) {
	return json.Marshal(walRecord{Operation: operation, Session: clone(candidate)})
}

func (w *WAL) RecoveryCounter() uint8 {
	if w == nil {
		return 0
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.journal.RecoveryCounter()
}

func (w *WAL) Stats() WALStats {
	if w == nil {
		return WALStats{}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.journal.Stats()
}

func (w *WAL) Close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.journal.Close()
}

func decodeWALRecord(raw []byte) (walRecord, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var record walRecord
	if err := decoder.Decode(&record); err != nil {
		return walRecord{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return walRecord{}, errors.New("multiple JSON values")
		}
		return walRecord{}, err
	}
	if err := validateWALSession(record.Session); err != nil {
		return walRecord{}, err
	}
	return record, nil
}

func validateWALSession(candidate Session) error {
	if candidate.ID == 0 || candidate.Revision == 0 || candidate.CreatedAt.IsZero() || candidate.UpdatedAt.IsZero() {
		return fmt.Errorf("%w: durable SGW-C identity, revision, and timestamps are required", ErrInvalidSession)
	}
	if candidate.UpdatedAt.Before(candidate.CreatedAt) {
		return fmt.Errorf("%w: durable SGW-C timestamps are reversed", ErrInvalidSession)
	}
	return validate(candidate)
}

func validWALUpdate(previous, next Session) bool {
	return next.ID == previous.ID && next.Revision == previous.Revision+1 &&
		next.SubscriberKey == previous.SubscriberKey && strings.EqualFold(next.APN, previous.APN) &&
		next.S11Control == previous.S11Control && next.MMEControl == previous.MMEControl &&
		next.PFCPControlSEID == previous.PFCPControlSEID && next.CreatedAt.Equal(previous.CreatedAt)
}
