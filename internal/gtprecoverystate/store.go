// Package gtprecoverystate durably records GTPv2-C peer restart counters
// without changing a gateway's subscriber-session WAL format. Keeping the
// journals separate preserves downgrade and rollback compatibility.
package gtprecoverystate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"github.com/lodestarnetworks/cups/internal/controlstate"
)

const (
	journalMagic = "LSNSGPR1"
	maxPeers     = 4096
)

type record struct {
	Key     string `json:"key"`
	Counter uint8  `json:"counter"`
}

type Store struct {
	mu            sync.Mutex
	journal       *controlstate.Journal
	counters      map[string]uint8
	snapshots     map[string][]byte
	snapshotBytes int64
}

func Open(path string, maxBytes int64, identity []byte) (*Store, error) {
	counters := make(map[string]uint8)
	journal, err := controlstate.OpenReplay(controlstate.Config{
		Path: path, Magic: journalMagic, Identity: identity, MaxBytes: maxBytes,
		MaxRecordBytes: 512,
	}, func(index uint64, raw []byte) error {
		record, err := decodeRecord(raw)
		if err != nil {
			return fmt.Errorf("peer-recovery record %d: %w", index, err)
		}
		counters[record.Key] = record.Counter
		if len(counters) > maxPeers {
			return fmt.Errorf("peer-recovery state exceeds %d entries", maxPeers)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("open GTP peer-recovery state: %w", err)
	}
	closeOnError := func(cause error) (*Store, error) {
		return nil, errors.Join(cause, journal.Close())
	}
	snapshots := make(map[string][]byte, len(counters))
	var snapshotBytes int64
	for key, counter := range counters {
		encoded, err := encodeRecord(key, counter)
		if err != nil {
			return closeOnError(err)
		}
		snapshots[key] = encoded
		snapshotBytes += controlstate.DataFrameBytes(len(encoded))
	}
	return &Store{journal: journal, counters: counters, snapshots: snapshots, snapshotBytes: snapshotBytes}, nil
}

func (s *Store) Start() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.journal.Start(); err != nil {
		return fmt.Errorf("start GTP peer-recovery state: %w", err)
	}
	return nil
}

func (s *Store) Snapshot() map[string]uint8 {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]uint8, len(s.counters))
	for key, counter := range s.counters {
		out[key] = counter
	}
	return out
}

func (s *Store) Commit(key string, counter uint8) error {
	if s == nil {
		return nil
	}
	if err := validateKey(key); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, ok := s.counters[key]; ok && current == counter {
		return nil
	}
	if _, exists := s.counters[key]; !exists && len(s.counters) >= maxPeers {
		return fmt.Errorf("peer-recovery state capacity %d reached", maxPeers)
	}
	encoded, err := encodeRecord(key, counter)
	if err != nil {
		return err
	}
	if s.journal.NeedsCompaction(s.snapshotBytes, len(encoded)) {
		if err := s.compactLocked(); err != nil {
			return fmt.Errorf("compact GTP peer-recovery state: %w", err)
		}
	}
	if err := s.journal.Append(encoded); err != nil {
		return fmt.Errorf("commit GTP peer-recovery state: %w", err)
	}
	if prior, ok := s.snapshots[key]; ok {
		s.snapshotBytes -= controlstate.DataFrameBytes(len(prior))
	}
	s.counters[key] = counter
	s.snapshots[key] = encoded
	s.snapshotBytes += controlstate.DataFrameBytes(len(encoded))
	return nil
}

func (s *Store) compactLocked() error {
	keys := make([]string, 0, len(s.snapshots))
	for key := range s.snapshots {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	records := make([][]byte, 0, len(keys))
	for _, key := range keys {
		records = append(records, s.snapshots[key])
	}
	return s.journal.Compact(records)
}

func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.journal.Close()
}

func encodeRecord(key string, counter uint8) ([]byte, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}
	return json.Marshal(record{Key: key, Counter: counter})
}

func decodeRecord(raw []byte) (record, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value record
	if err := decoder.Decode(&value); err != nil {
		return record{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return record{}, errors.New("multiple JSON values")
		}
		return record{}, err
	}
	if err := validateKey(value.Key); err != nil {
		return record{}, err
	}
	return value, nil
}

func validateKey(key string) error {
	side, rawPeer, ok := strings.Cut(key, "|")
	if !ok || side != "s11" && side != "s5" {
		return errors.New("peer-recovery key must identify s11 or s5")
	}
	peer, err := netip.ParseAddrPort(rawPeer)
	if err != nil || !peer.Addr().Is4() || peer.Port() == 0 || peer.String() != rawPeer {
		return errors.New("peer-recovery key must contain a canonical IPv4 endpoint")
	}
	return nil
}
