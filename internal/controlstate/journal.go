// Package controlstate provides the durable, single-writer transition journal
// shared by the SGW-C and PGW-C session stores.
package controlstate

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	journalFormatVersion = 1
	recordFormatVersion  = 1
	recordTypeBoot       = 1
	recordTypeData       = 2
	headerBytes          = 48
	recordHeaderBytes    = 8
	DefaultMaxBytes      = int64(1 << 30)
	DefaultMaxRecord     = 1 << 20
)

var (
	ErrCorrupt  = errors.New("control-state journal is corrupt")
	ErrLocked   = errors.New("control-state journal is locked by another process")
	ErrCapacity = errors.New("control-state journal capacity reached")
	crcTable    = crc32.MakeTable(crc32.Castagnoli)
)

type Config struct {
	Path           string
	Magic          string
	Identity       []byte
	MaxBytes       int64
	MaxRecordBytes int
	RecoverySeed   uint8
}

type Stats struct {
	Bytes           int64
	Records         uint64
	DataRecords     uint64
	Starts          uint64
	Compactions     uint64
	RecoveryCounter uint8
	RecoveredTail   bool
}

// Journal is a checksummed fsync-before-acknowledgement log. A stable lock file
// plus the current journal inode fence ownership across atomic compaction, so
// only one control-plane owner can use an identity at a time.
type Journal struct {
	mu        sync.Mutex
	directory *os.File
	lock      *os.File
	file      *os.File
	path      string
	base      string
	header    []byte
	maxBytes  int64
	maxRecord int
	stats     Stats
	failed    error
	started   bool
	closed    bool
}

func Open(raw Config) (*Journal, [][]byte, error) {
	return open(raw, nil)
}

// OpenReplay verifies and streams each data record to consume while retaining
// the same lock and two-phase Start contract as Open. The record slice is only
// valid for the duration of consume and must not be retained by the callback.
func OpenReplay(raw Config, consume func(index uint64, record []byte) error) (*Journal, error) {
	if consume == nil {
		return nil, errors.New("control-state replay callback is required")
	}
	journal, _, err := open(raw, consume)
	return journal, err
}

func open(raw Config, consume func(index uint64, record []byte) error) (*Journal, [][]byte, error) {
	config, err := normalizeConfig(raw)
	if err != nil {
		return nil, nil, err
	}
	parentPath := filepath.Dir(config.Path)
	parentFD, err := unix.Open(parentPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open control-state directory %q: %w", parentPath, err)
	}
	directory := os.NewFile(uintptr(parentFD), parentPath)
	if directory == nil {
		_ = unix.Close(parentFD)
		return nil, nil, fmt.Errorf("open control-state directory %q: invalid file descriptor", parentPath)
	}
	closeDirectory := func(cause error) (*Journal, [][]byte, error) {
		return nil, nil, errors.Join(cause, directory.Close())
	}
	var parent unix.Stat_t
	if err := unix.Fstat(parentFD, &parent); err != nil {
		return closeDirectory(fmt.Errorf("inspect control-state directory %q: %w", parentPath, err))
	}
	if parent.Mode&unix.S_IFMT != unix.S_IFDIR || parent.Uid != uint32(os.Geteuid()) || parent.Mode&0o022 != 0 {
		return closeDirectory(fmt.Errorf("control-state directory %q must be owned by uid %d and not writable by group or others", parentPath, os.Geteuid()))
	}

	base := filepath.Base(config.Path)
	lockFile, lockCreated, err := openOwnedRegularAt(parentFD, base+".lock")
	if err != nil {
		return closeDirectory(fmt.Errorf("open control-state lock %q: %w", config.Path+".lock", err))
	}
	closeLock := func(cause error) (*Journal, [][]byte, error) {
		return nil, nil, errors.Join(cause, lockFile.Close(), directory.Close())
	}
	if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return closeLock(fmt.Errorf("%w: %s", ErrLocked, config.Path))
		}
		return closeLock(fmt.Errorf("lock control-state owner fence %q: %w", config.Path+".lock", err))
	}
	staleCompactionsRemoved, err := cleanupStaleCompactions(parentFD, base)
	if err != nil {
		_ = unix.Flock(int(lockFile.Fd()), unix.LOCK_UN)
		return closeLock(fmt.Errorf("clean stale control-state compaction files: %w", err))
	}

	file, fileCreated, err := openOwnedRegularAt(parentFD, base)
	if err != nil {
		_ = unix.Flock(int(lockFile.Fd()), unix.LOCK_UN)
		return closeLock(fmt.Errorf("open control-state journal %q: %w", config.Path, err))
	}
	closeOnError := func(cause error) (*Journal, [][]byte, error) {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		_ = file.Close()
		_ = unix.Flock(int(lockFile.Fd()), unix.LOCK_UN)
		return nil, nil, errors.Join(cause, lockFile.Close(), directory.Close())
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return closeOnError(fmt.Errorf("%w: %s", ErrLocked, config.Path))
		}
		return closeOnError(fmt.Errorf("lock control-state journal %q: %w", config.Path, err))
	}

	state, err := file.Stat()
	if err != nil {
		return closeOnError(fmt.Errorf("inspect control-state journal %q: %w", config.Path, err))
	}
	expectedHeader := makeHeader(config.Magic, config.Identity)
	journal := &Journal{
		directory: directory, lock: lockFile, file: file, path: config.Path, base: base,
		header: expectedHeader, maxBytes: config.MaxBytes, maxRecord: config.MaxRecordBytes,
	}
	records, lastCounter, haveCounter, err := journal.replay(state.Size(), config, consume)
	if err != nil {
		return closeOnError(err)
	}
	counter := config.RecoverySeed
	if haveCounter {
		counter = lastCounter + 1
	}
	journal.stats.RecoveryCounter = counter
	if lockCreated || fileCreated || staleCompactionsRemoved {
		if err := unix.Fsync(parentFD); err != nil {
			return closeOnError(fmt.Errorf("sync control-state directory %q: %w", parentPath, err))
		}
	}
	return journal, records, nil
}

func cleanupStaleCompactions(parentFD int, base string) (bool, error) {
	directoryFD, err := unix.Openat(parentFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return false, err
	}
	directory := os.NewFile(uintptr(directoryFD), ".")
	if directory == nil {
		_ = unix.Close(directoryFD)
		return false, errors.New("invalid directory file descriptor")
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return false, errors.Join(readErr, closeErr)
	}
	prefix := "." + base + ".compact-"
	removed := false
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		suffix := strings.TrimPrefix(name, prefix)
		if len(suffix) != 24 {
			continue
		}
		if _, err := hex.DecodeString(suffix); err != nil {
			continue
		}
		var state unix.Stat_t
		if err := unix.Fstatat(parentFD, name, &state, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			return removed, err
		}
		if state.Mode&unix.S_IFMT != unix.S_IFREG || state.Nlink != 1 || state.Uid != uint32(os.Geteuid()) || state.Mode&0o077 != 0 {
			return removed, fmt.Errorf("unsafe stale compaction file %q", name)
		}
		if err := unix.Unlinkat(parentFD, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return removed, err
		}
		removed = true
	}
	return removed, nil
}

func openOwnedRegularAt(parentFD int, name string) (*os.File, bool, error) {
	openFlags := unix.O_RDWR | unix.O_APPEND | unix.O_CLOEXEC | unix.O_NOFOLLOW
	fd, err := unix.Openat(parentFD, name, openFlags, 0)
	created := false
	if errors.Is(err, unix.ENOENT) {
		fd, err = unix.Openat(parentFD, name, openFlags|unix.O_CREAT|unix.O_EXCL, 0o600)
		created = err == nil
		if errors.Is(err, unix.EEXIST) {
			fd, err = unix.Openat(parentFD, name, openFlags, 0)
			created = false
		}
	}
	if err != nil {
		return nil, false, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, false, errors.New("invalid file descriptor")
	}
	var state unix.Stat_t
	if err := unix.Fstat(fd, &state); err != nil {
		_ = file.Close()
		return nil, false, err
	}
	if state.Mode&unix.S_IFMT != unix.S_IFREG || state.Nlink != 1 || state.Uid != uint32(os.Geteuid()) || state.Mode&0o077 != 0 {
		_ = file.Close()
		return nil, false, fmt.Errorf("must be a single-link regular file owned by uid %d with mode 0600 or stricter", os.Geteuid())
	}
	return file, created, nil
}

func normalizeConfig(config Config) (Config, error) {
	config.Path = filepath.Clean(config.Path)
	if config.Path == "." || config.Path == string(filepath.Separator) || !filepath.IsAbs(config.Path) {
		return Config{}, errors.New("control-state journal path must be an absolute non-root file path")
	}
	if len(config.Magic) != 8 {
		return Config{}, errors.New("control-state journal magic must contain exactly 8 bytes")
	}
	if len(config.Identity) == 0 {
		return Config{}, errors.New("control-state journal identity is required")
	}
	if config.MaxBytes == 0 {
		config.MaxBytes = DefaultMaxBytes
	}
	if config.MaxRecordBytes == 0 {
		config.MaxRecordBytes = DefaultMaxRecord
	}
	if config.MaxRecordBytes < 64 || config.MaxRecordBytes > 64<<20 {
		return Config{}, errors.New("control-state maximum record size must be between 64 bytes and 64 MiB")
	}
	if config.MaxBytes < headerBytes+recordHeaderBytes+3 {
		return Config{}, errors.New("control-state maximum journal size is too small")
	}
	return config, nil
}

func (j *Journal) Append(data []byte) error {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return errors.New("control-state journal is closed")
	}
	if j.failed != nil {
		return fmt.Errorf("control-state journal previously failed: %w", j.failed)
	}
	if !j.started {
		return errors.New("control-state journal startup has not been committed")
	}
	if len(data) == 0 || len(data) > j.maxRecord {
		return fmt.Errorf("control-state record length %d is outside 1-%d", len(data), j.maxRecord)
	}
	payload := make([]byte, 2+len(data))
	payload[0] = recordTypeData
	payload[1] = recordFormatVersion
	copy(payload[2:], data)
	if err := j.appendFrame(payload, true); err != nil {
		j.failed = err
		return err
	}
	j.stats.DataRecords++
	return nil
}

// Start durably records that the component accepted the fully decoded journal
// and is beginning a new ownership epoch. Callers must validate every replayed
// data record before invoking Start.
func (j *Journal) Start() error {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return errors.New("control-state journal is closed")
	}
	if j.failed != nil {
		return fmt.Errorf("control-state journal previously failed: %w", j.failed)
	}
	if j.started {
		return nil
	}
	if err := j.appendFrame([]byte{recordTypeBoot, recordFormatVersion, j.stats.RecoveryCounter}, true); err != nil {
		j.failed = err
		return fmt.Errorf("record control-plane startup: %w", err)
	}
	j.stats.Starts++
	j.started = true
	return nil
}

// DataFrameBytes returns the on-disk bytes required by one data record.
func DataFrameBytes(dataLength int) int64 {
	if dataLength < 0 {
		return 0
	}
	return int64(recordHeaderBytes + 2 + dataLength)
}

// NeedsCompaction reports whether replacing obsolete transitions with the
// caller's live snapshot is warranted before appending the next record.
// snapshotFrameBytes is the sum of DataFrameBytes for that snapshot.
func (j *Journal) NeedsCompaction(snapshotFrameBytes int64, nextDataLength int) bool {
	if j == nil {
		return false
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.failed != nil || !j.started || snapshotFrameBytes < 0 || nextDataLength < 1 {
		return false
	}
	compactBytes := int64(headerBytes) + int64(recordHeaderBytes+3) + snapshotFrameBytes
	projected := j.stats.Bytes + DataFrameBytes(nextDataLength)
	if projected > j.maxBytes {
		return compactBytes+DataFrameBytes(nextDataLength) <= j.maxBytes
	}
	return j.stats.Bytes >= j.maxBytes/2 && j.stats.Bytes-compactBytes >= j.maxBytes/4
}

// Compact atomically replaces obsolete transitions with a caller-validated
// snapshot. A separate, stable lock file remains held across the rename, and
// both the old and replacement journal inodes are locked to fence older
// binaries that only understand the journal-file lock.
func (j *Journal) Compact(records [][]byte) error {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return errors.New("control-state journal is closed")
	}
	if j.failed != nil {
		return fmt.Errorf("control-state journal previously failed: %w", j.failed)
	}
	if !j.started {
		return errors.New("control-state journal startup has not been committed")
	}
	totalBytes := int64(headerBytes + recordHeaderBytes + 3)
	for index, record := range records {
		if len(record) == 0 || len(record) > j.maxRecord {
			return fmt.Errorf("control-state snapshot record %d length %d is outside 1-%d", index, len(record), j.maxRecord)
		}
		totalBytes += DataFrameBytes(len(record))
		if totalBytes > j.maxBytes {
			return ErrCapacity
		}
	}

	random := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return fmt.Errorf("generate control-state compaction name: %w", err)
	}
	temporaryBase := "." + j.base + ".compact-" + hex.EncodeToString(random)
	fd, err := unix.Openat(int(j.directory.Fd()), temporaryBase,
		unix.O_RDWR|unix.O_APPEND|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_CREAT|unix.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create compacted control-state journal: %w", err)
	}
	replacement := os.NewFile(uintptr(fd), temporaryBase)
	if replacement == nil {
		_ = unix.Close(fd)
		_ = unix.Unlinkat(int(j.directory.Fd()), temporaryBase, 0)
		return errors.New("create compacted control-state journal: invalid file descriptor")
	}
	renamed := false
	cleanupReplacement := func() {
		_ = unix.Flock(fd, unix.LOCK_UN)
		_ = replacement.Close()
		if !renamed {
			_ = unix.Unlinkat(int(j.directory.Fd()), temporaryBase, 0)
		}
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		cleanupReplacement()
		return fmt.Errorf("lock compacted control-state journal: %w", err)
	}
	if err := writeFull(replacement, j.header); err != nil {
		cleanupReplacement()
		return fmt.Errorf("write compacted control-state header: %w", err)
	}
	bootFrame := makeFrame([]byte{recordTypeBoot, recordFormatVersion, j.stats.RecoveryCounter})
	if err := writeFull(replacement, bootFrame); err != nil {
		cleanupReplacement()
		return fmt.Errorf("write compacted control-state startup: %w", err)
	}
	for index, record := range records {
		payload := make([]byte, 2+len(record))
		payload[0] = recordTypeData
		payload[1] = recordFormatVersion
		copy(payload[2:], record)
		if err := writeFull(replacement, makeFrame(payload)); err != nil {
			cleanupReplacement()
			return fmt.Errorf("write compacted control-state record %d: %w", index, err)
		}
	}
	if err := replacement.Sync(); err != nil {
		cleanupReplacement()
		return fmt.Errorf("sync compacted control-state journal: %w", err)
	}
	var currentPath, currentFile unix.Stat_t
	if err := unix.Fstatat(int(j.directory.Fd()), j.base, &currentPath, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		cleanupReplacement()
		return fmt.Errorf("inspect current control-state path before compaction: %w", err)
	}
	if err := unix.Fstat(int(j.file.Fd()), &currentFile); err != nil {
		cleanupReplacement()
		return fmt.Errorf("inspect current control-state file before compaction: %w", err)
	}
	if currentPath.Mode&unix.S_IFMT != unix.S_IFREG || currentPath.Dev != currentFile.Dev || currentPath.Ino != currentFile.Ino {
		cleanupReplacement()
		return errors.New("control-state journal path changed during compaction")
	}
	if err := unix.Renameat(int(j.directory.Fd()), temporaryBase, int(j.directory.Fd()), j.base); err != nil {
		cleanupReplacement()
		return fmt.Errorf("install compacted control-state journal: %w", err)
	}
	renamed = true

	old := j.file
	j.file = replacement
	j.stats.Bytes = totalBytes
	j.stats.Records += uint64(len(records) + 1)
	j.stats.DataRecords += uint64(len(records))
	j.stats.Compactions++
	unlockOldErr := unix.Flock(int(old.Fd()), unix.LOCK_UN)
	closeOldErr := old.Close()
	if err := unix.Fsync(int(j.directory.Fd())); err != nil {
		j.failed = fmt.Errorf("sync compacted control-state directory: %w", err)
		return errors.Join(j.failed, unlockOldErr, closeOldErr)
	}
	if err := errors.Join(unlockOldErr, closeOldErr); err != nil {
		j.failed = fmt.Errorf("release obsolete control-state journal: %w", err)
		return j.failed
	}
	return nil
}

func (j *Journal) RecoveryCounter() uint8 {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.stats.RecoveryCounter
}

func (j *Journal) Stats() Stats {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.stats
}

func (j *Journal) Close() error {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil
	}
	j.closed = true
	fileUnlockErr := unix.Flock(int(j.file.Fd()), unix.LOCK_UN)
	fileCloseErr := j.file.Close()
	lockUnlockErr := unix.Flock(int(j.lock.Fd()), unix.LOCK_UN)
	return errors.Join(fileUnlockErr, fileCloseErr, lockUnlockErr, j.lock.Close(), j.directory.Close())
}

func (j *Journal) replay(size int64, config Config, consume func(index uint64, record []byte) error) ([][]byte, uint8, bool, error) {
	if size > j.maxBytes {
		return nil, 0, false, fmt.Errorf("%w: journal size %d exceeds limit %d", ErrCapacity, size, j.maxBytes)
	}
	expectedHeader := makeHeader(config.Magic, config.Identity)
	if size == 0 {
		if err := writeFull(j.file, expectedHeader); err != nil {
			return nil, 0, false, fmt.Errorf("initialize control-state journal: %w", err)
		}
		if err := j.file.Sync(); err != nil {
			return nil, 0, false, fmt.Errorf("sync new control-state journal: %w", err)
		}
		size = headerBytes
	}
	if size < headerBytes {
		return nil, 0, false, fmt.Errorf("%w: truncated file header", ErrCorrupt)
	}
	header := make([]byte, headerBytes)
	if _, err := j.file.ReadAt(header, 0); err != nil {
		return nil, 0, false, fmt.Errorf("read control-state header: %w", err)
	}
	if !equalBytes(header, expectedHeader) {
		return nil, 0, false, fmt.Errorf("%w: header, component, or configuration identity mismatch", ErrCorrupt)
	}

	records := make([][]byte, 0)
	offset := int64(headerBytes)
	var lastCounter uint8
	var haveCounter bool
	for offset < size {
		if size-offset < recordHeaderBytes {
			if err := j.truncateTail(offset); err != nil {
				return nil, 0, false, err
			}
			size = offset
			break
		}
		header := make([]byte, recordHeaderBytes)
		if _, err := j.file.ReadAt(header, offset); err != nil {
			return nil, 0, false, fmt.Errorf("read control-state record header at %d: %w", offset, err)
		}
		length := int64(binary.BigEndian.Uint32(header[0:4]))
		if length < 3 || length > int64(j.maxRecord+2) {
			return nil, 0, false, fmt.Errorf("%w: invalid record length %d at %d", ErrCorrupt, length, offset)
		}
		if size-offset-recordHeaderBytes < length {
			if err := j.truncateTail(offset); err != nil {
				return nil, 0, false, err
			}
			size = offset
			break
		}
		payload := make([]byte, length)
		if _, err := j.file.ReadAt(payload, offset+recordHeaderBytes); err != nil {
			return nil, 0, false, fmt.Errorf("read control-state record at %d: %w", offset, err)
		}
		if got, want := crc32.Checksum(payload, crcTable), binary.BigEndian.Uint32(header[4:8]); got != want {
			return nil, 0, false, fmt.Errorf("%w: checksum mismatch at %d", ErrCorrupt, offset)
		}
		if payload[1] != recordFormatVersion {
			return nil, 0, false, fmt.Errorf("%w: unsupported record version at %d", ErrCorrupt, offset)
		}
		switch payload[0] {
		case recordTypeBoot:
			if len(payload) != 3 {
				return nil, 0, false, fmt.Errorf("%w: malformed startup record at %d", ErrCorrupt, offset)
			}
			if haveCounter && payload[2] != lastCounter+1 {
				return nil, 0, false, fmt.Errorf("%w: non-monotonic recovery counter at %d", ErrCorrupt, offset)
			}
			lastCounter = payload[2]
			haveCounter = true
			j.stats.Starts++
		case recordTypeData:
			if !haveCounter {
				return nil, 0, false, fmt.Errorf("%w: data precedes startup record at %d", ErrCorrupt, offset)
			}
			if consume != nil {
				if err := consume(j.stats.DataRecords, payload[2:]); err != nil {
					return nil, 0, false, fmt.Errorf("replay control-state data record %d: %w", j.stats.DataRecords, err)
				}
			} else {
				records = append(records, append([]byte(nil), payload[2:]...))
			}
			j.stats.DataRecords++
		default:
			return nil, 0, false, fmt.Errorf("%w: unknown record type %d at %d", ErrCorrupt, payload[0], offset)
		}
		j.stats.Records++
		offset += recordHeaderBytes + length
	}
	j.stats.Bytes = size
	return records, lastCounter, haveCounter, nil
}

func makeHeader(magic string, identity []byte) []byte {
	header := make([]byte, headerBytes)
	copy(header[0:8], magic)
	header[8] = journalFormatVersion
	digest := sha256.Sum256(identity)
	copy(header[12:44], digest[:])
	binary.BigEndian.PutUint32(header[44:48], crc32.Checksum(header[:44], crcTable))
	return header
}

func (j *Journal) appendFrame(payload []byte, syncFile bool) error {
	record := makeFrame(payload)
	if j.stats.Bytes+int64(len(record)) > j.maxBytes {
		return ErrCapacity
	}
	if err := writeFull(j.file, record); err != nil {
		return fmt.Errorf("append control-state journal: %w", err)
	}
	if syncFile {
		if err := j.file.Sync(); err != nil {
			return fmt.Errorf("sync control-state journal: %w", err)
		}
	}
	j.stats.Bytes += int64(len(record))
	j.stats.Records++
	return nil
}

func makeFrame(payload []byte) []byte {
	record := make([]byte, recordHeaderBytes+len(payload))
	binary.BigEndian.PutUint32(record[0:4], uint32(len(payload)))
	binary.BigEndian.PutUint32(record[4:8], crc32.Checksum(payload, crcTable))
	copy(record[8:], payload)
	return record
}

func (j *Journal) truncateTail(offset int64) error {
	if err := j.file.Truncate(offset); err != nil {
		return fmt.Errorf("truncate partial control-state tail: %w", err)
	}
	if err := j.file.Sync(); err != nil {
		return fmt.Errorf("sync truncated control-state tail: %w", err)
	}
	j.stats.RecoveredTail = true
	return nil
}

func writeFull(file *os.File, data []byte) error {
	for len(data) > 0 {
		written, err := file.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}
