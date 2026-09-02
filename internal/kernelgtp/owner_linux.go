//go:build linux

package kernelgtp

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	ownerRecordVersion = 1
	ownerRecordMaxSize = 1_024
)

type ownerRecord struct {
	Version  int    `json:"version"`
	LinkName string `json:"link_name"`
	Token    string `json:"token"`
}

// ownerLease is both the durable identity of one configured GTP link and the
// live-process fence for it. flock is released by the kernel after SIGKILL,
// while the random token remains available for ownership-verified recovery.
type ownerLease struct {
	file   *os.File
	path   string
	token  string
	alias  string
	closed bool
}

func acquireOwnerLease(config LinkConfig) (_ *ownerLease, resultErr error) {
	parentPath := filepath.Dir(config.OwnershipFile)
	parentFD, err := unix.Open(parentPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open kernel GTP ownership directory %q: %w", parentPath, err)
	}
	defer func() { resultErr = errors.Join(resultErr, unix.Close(parentFD)) }()

	var parent unix.Stat_t
	if err := unix.Fstat(parentFD, &parent); err != nil {
		return nil, fmt.Errorf("inspect kernel GTP ownership directory %q: %w", parentPath, err)
	}
	if parent.Mode&unix.S_IFMT != unix.S_IFDIR || parent.Uid != uint32(os.Geteuid()) || parent.Mode&0o022 != 0 {
		return nil, fmt.Errorf("%w: ownership directory %q must be owned by uid %d and not writable by group or others", ErrInvalid, parentPath, os.Geteuid())
	}

	fd, err := unix.Openat(parentFD, filepath.Base(config.OwnershipFile), unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open kernel GTP ownership file %q: %w", config.OwnershipFile, err)
	}
	file := os.NewFile(uintptr(fd), config.OwnershipFile)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open kernel GTP ownership file %q: invalid file descriptor", config.OwnershipFile)
	}
	lease := &ownerLease{file: file, path: config.OwnershipFile}
	keep := false
	defer func() {
		if !keep {
			resultErr = errors.Join(resultErr, lease.Close())
		}
	}()

	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, fmt.Errorf("acquire kernel GTP ownership fence %q: %w", config.OwnershipFile, ErrOwnerActive)
		}
		return nil, fmt.Errorf("acquire kernel GTP ownership fence %q: %w", config.OwnershipFile, err)
	}

	var state unix.Stat_t
	if err := unix.Fstat(fd, &state); err != nil {
		return nil, fmt.Errorf("inspect kernel GTP ownership file %q: %w", config.OwnershipFile, err)
	}
	if state.Mode&unix.S_IFMT != unix.S_IFREG || state.Nlink != 1 || state.Uid != uint32(os.Geteuid()) || state.Mode&0o077 != 0 {
		return nil, fmt.Errorf("%w: ownership file %q must be a single-link regular file owned by uid %d with mode 0600 or stricter", ErrInvalid, config.OwnershipFile, os.Geteuid())
	}
	if state.Size < 0 || state.Size > ownerRecordMaxSize {
		return nil, fmt.Errorf("%w: ownership file %q has invalid size %d", ErrInvalid, config.OwnershipFile, state.Size)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek kernel GTP ownership file %q: %w", config.OwnershipFile, err)
	}
	contents, err := io.ReadAll(io.LimitReader(file, ownerRecordMaxSize+1))
	if err != nil {
		return nil, fmt.Errorf("read kernel GTP ownership file %q: %w", config.OwnershipFile, err)
	}

	var record ownerRecord
	if len(contents) == 0 {
		record, err = newOwnerRecord(config.Name)
		if err != nil {
			return nil, err
		}
		if err := writeOwnerRecord(file, record); err != nil {
			return nil, fmt.Errorf("initialize kernel GTP ownership file %q: %w", config.OwnershipFile, err)
		}
	} else {
		decoder := json.NewDecoder(bytes.NewReader(contents))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&record); err != nil {
			return nil, fmt.Errorf("%w: decode ownership file %q: %v", ErrInvalid, config.OwnershipFile, err)
		}
		if err := requireJSONEOF(decoder); err != nil {
			return nil, fmt.Errorf("%w: decode ownership file %q: %v", ErrInvalid, config.OwnershipFile, err)
		}
	}
	if record.Version != ownerRecordVersion || record.LinkName != config.Name || !validOwnerToken(record.Token) {
		return nil, fmt.Errorf("%w: ownership file %q does not match link %q", ErrInvalid, config.OwnershipFile, config.Name)
	}
	lease.token = record.Token
	lease.alias = ownershipAliasPrefix + record.Token
	keep = true
	return lease, nil
}

func newOwnerRecord(linkName string) (ownerRecord, error) {
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return ownerRecord{}, fmt.Errorf("generate kernel GTP ownership token: %w", err)
	}
	return ownerRecord{Version: ownerRecordVersion, LinkName: linkName, Token: hex.EncodeToString(token[:])}, nil
}

func writeOwnerRecord(file *os.File, record ownerRecord) error {
	contents, err := json.Marshal(record)
	if err != nil {
		return err
	}
	contents = append(contents, '\n')
	if err := file.Truncate(0); err != nil {
		return err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if _, err := file.Write(contents); err != nil {
		return err
	}
	return file.Sync()
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("multiple JSON values")
	}
	return err
}

func validOwnerToken(token string) bool {
	if len(token) != 64 || token != strings.ToLower(token) {
		return false
	}
	decoded, err := hex.DecodeString(token)
	return err == nil && len(decoded) == 32
}

func isOwnershipAlias(alias string) bool {
	return strings.HasPrefix(alias, ownershipAliasPrefix) && validOwnerToken(strings.TrimPrefix(alias, ownershipAliasPrefix))
}

func (l *ownerLease) Close() error {
	if l == nil || l.closed {
		return nil
	}
	l.closed = true
	var result error
	if err := unix.Flock(int(l.file.Fd()), unix.LOCK_UN); err != nil {
		result = errors.Join(result, fmt.Errorf("release kernel GTP ownership fence %q: %w", l.path, err))
	}
	if err := l.file.Close(); err != nil {
		result = errors.Join(result, fmt.Errorf("close kernel GTP ownership file %q: %w", l.path, err))
	}
	return result
}
