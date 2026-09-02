package controlstate

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func testConfig(path string) Config {
	return Config{
		Path: path, Magic: "LSNCPST1", Identity: []byte("component=test;site=london"),
		MaxBytes: 1 << 20, MaxRecordBytes: 1 << 16, RecoverySeed: 7,
	}
}

func TestJournalRoundTripFenceAndRecoveryCounter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.wal")
	first, records, err := Open(testConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 || first.RecoveryCounter() != 7 {
		t.Fatalf("new journal records=%q counter=%d", records, first.RecoveryCounter())
	}
	if _, _, err := Open(testConfig(path)); !errors.Is(err, ErrLocked) {
		t.Fatalf("second owner error = %v, want ErrLocked", err)
	}
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	if err := first.Append([]byte("first transition")); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second, records, err := Open(testConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if len(records) != 1 || string(records[0]) != "first transition" || second.RecoveryCounter() != 8 {
		t.Fatalf("reopened records=%q counter=%d", records, second.RecoveryCounter())
	}
	if err := second.Start(); err != nil {
		t.Fatal(err)
	}
	stats := second.Stats()
	if stats.Starts != 2 || stats.DataRecords != 1 || stats.Records != 3 || stats.RecoveredTail {
		t.Fatalf("journal stats = %+v", stats)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("journal mode = %04o, want 0600", info.Mode().Perm())
	}
}

func TestJournalTailRecoveryIdentityAndChecksumFailure(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "control.wal")
	journal, _, err := Open(testConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Start(); err != nil {
		t.Fatal(err)
	}
	if err := journal.Append([]byte("durable transition")); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
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
	recovered, records, err := Open(testConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	if !recovered.Stats().RecoveredTail || len(records) != 1 {
		t.Fatalf("tail recovery stats=%+v records=%q", recovered.Stats(), records)
	}
	if err := recovered.Start(); err != nil {
		t.Fatal(err)
	}
	if err := recovered.Close(); err != nil {
		t.Fatal(err)
	}

	wrongIdentity := testConfig(path)
	wrongIdentity.Identity = []byte("component=test;site=manchester")
	if _, _, err := Open(wrongIdentity); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("identity mismatch error = %v, want ErrCorrupt", err)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	contents[len(contents)-1] ^= 0xff
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(testConfig(path)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("checksum error = %v, want ErrCorrupt", err)
	}
}

func TestJournalStreamingReplayAndCallbackFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stream.wal")
	journal, _, err := Open(testConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Start(); err != nil {
		t.Fatal(err)
	}
	for _, record := range []string{"first", "second", "third"} {
		if err := journal.Append([]byte(record)); err != nil {
			t.Fatal(err)
		}
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	var streamed []string
	replayed, err := OpenReplay(testConfig(path), func(index uint64, record []byte) error {
		if index != uint64(len(streamed)) {
			return fmt.Errorf("index=%d, want %d", index, len(streamed))
		}
		streamed = append(streamed, string(record))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(streamed, ","); got != "first,second,third" {
		t.Fatalf("streamed records = %q", got)
	}
	if err := replayed.Close(); err != nil {
		t.Fatal(err)
	}

	sentinel := errors.New("semantic rejection")
	if _, err := OpenReplay(testConfig(path), func(index uint64, _ []byte) error {
		if index == 1 {
			return sentinel
		}
		return nil
	}); !errors.Is(err, sentinel) {
		t.Fatalf("streaming callback error = %v, want sentinel", err)
	}
	// Callback failure must release both fences and must not append a startup.
	audit, records, err := Open(testConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	if len(records) != 3 || audit.Stats().Starts != 1 {
		t.Fatalf("failed streaming replay changed journal: records=%d stats=%+v", len(records), audit.Stats())
	}
}

func TestJournalBoundsAndUnsafePaths(t *testing.T) {
	directory := t.TempDir()
	config := testConfig(filepath.Join(directory, "bounded.wal"))
	config.MaxBytes = headerBytes + recordHeaderBytes + 3
	journal, _, err := Open(config)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	if err := journal.Start(); err != nil {
		t.Fatal(err)
	}
	if err := journal.Append([]byte("cannot fit")); !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity error = %v, want ErrCapacity", err)
	}

	unsafeDirectory := filepath.Join(directory, "unsafe")
	if err := os.Mkdir(unsafeDirectory, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafeDirectory, 0o777); err != nil {
		t.Fatal(err)
	}
	unsafe := testConfig(filepath.Join(unsafeDirectory, "state.wal"))
	if _, _, err := Open(unsafe); err == nil {
		t.Fatal("journal accepted a group/world-writable parent directory")
	}
	if _, _, err := Open(Config{Path: "relative.wal", Magic: "LSNCPST1", Identity: []byte("x")}); err == nil {
		t.Fatal("journal accepted a relative path")
	}
}

func TestJournalRequiresStartAndCompactsAtomically(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "compact.wal")
	journal, _, err := Open(testConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Append([]byte("before start")); err == nil {
		t.Fatal("journal accepted data before its startup epoch")
	}
	if err := journal.Start(); err != nil {
		t.Fatal(err)
	}
	if err := journal.Append([]byte("obsolete one")); err != nil {
		t.Fatal(err)
	}
	if err := journal.Append([]byte("obsolete two")); err != nil {
		t.Fatal(err)
	}
	if err := journal.Compact([][]byte{[]byte("current one"), []byte("current two")}); err != nil {
		t.Fatal(err)
	}
	stats := journal.Stats()
	if stats.Compactions != 1 || stats.Starts != 1 || stats.DataRecords != 4 || stats.Records != 6 {
		t.Fatalf("compacted stats = %+v", stats)
	}

	// The replacement inode itself remains locked, fencing an older binary
	// that does not know about the separate stable lock file.
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_APPEND|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
		_ = unix.Close(fd)
		t.Fatalf("replacement journal lock error = %v, want would-block", err)
	}
	_ = unix.Close(fd)
	if _, _, err := Open(testConfig(path)); !errors.Is(err, ErrLocked) {
		t.Fatalf("second owner after compaction error = %v, want ErrLocked", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, records, err := Open(testConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if got := fmt.Sprintf("%s,%s", records[0], records[1]); got != "current one,current two" {
		t.Fatalf("compacted records = %q", got)
	}
	if reopened.RecoveryCounter() != 8 {
		t.Fatalf("recovery counter after compaction = %d, want 8", reopened.RecoveryCounter())
	}
	matches, err := filepath.Glob(filepath.Join(directory, ".compact.wal.compact-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("compaction temporary files = %v, error=%v", matches, err)
	}
}

func TestJournalRejectsSymlinksAndHardlinks(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "symlink.wal")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(testConfig(symlink)); err == nil {
		t.Fatal("journal accepted a symlink")
	}
	hardlink := filepath.Join(directory, "hardlink.wal")
	if err := os.Link(target, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(testConfig(hardlink)); err == nil {
		t.Fatal("journal accepted a multiply-linked state file")
	}

	lockPath := filepath.Join(directory, "unsafe-lock.wal.lock")
	if err := os.Link(target, lockPath); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(testConfig(filepath.Join(directory, "unsafe-lock.wal"))); err == nil {
		t.Fatal("journal accepted a multiply-linked owner fence")
	}
}

func TestJournalCleansOnlySafeStaleCompactionFiles(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "state.wal")
	stale := filepath.Join(directory, ".state.wal.compact-00112233445566778899aabb")
	if err := os.WriteFile(stale, []byte("partial replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	journal, _, err := Open(testConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale compaction still exists or cannot be inspected: %v", err)
	}

	unsafeDirectory := t.TempDir()
	unsafePath := filepath.Join(unsafeDirectory, "state.wal")
	unsafeStale := filepath.Join(unsafeDirectory, ".state.wal.compact-aabbccddeeff001122334455")
	if err := os.Symlink(filepath.Join(unsafeDirectory, "missing"), unsafeStale); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(testConfig(unsafePath)); err == nil {
		t.Fatal("journal silently removed or accepted an unsafe stale compaction path")
	}
	if info, err := os.Lstat(unsafeStale); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("unsafe stale path was changed: info=%v error=%v", info, err)
	}
}

func TestJournalRecoversAfterSIGKILL(t *testing.T) {
	if os.Getenv("SGW_NEXT_CONTROLSTATE_KILL_HELPER") == "1" {
		journal, _, err := Open(testConfig(os.Getenv("SGW_NEXT_CONTROLSTATE_KILL_PATH")))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if err := journal.Start(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if err := journal.Append([]byte("fsynced before SIGKILL")); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		fmt.Println("ready")
		for {
			time.Sleep(time.Hour)
		}
	}

	path := filepath.Join(t.TempDir(), "killed.wal")
	command := exec.Command(os.Args[0], "-test.run=^TestJournalRecoversAfterSIGKILL$")
	command.Env = append(os.Environ(),
		"SGW_NEXT_CONTROLSTATE_KILL_HELPER=1",
		"SGW_NEXT_CONTROLSTATE_KILL_PATH="+path,
	)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	ready := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(stdout).ReadString('\n')
		ready <- strings.TrimSpace(line)
	}()
	select {
	case line := <-ready:
		if line != "ready" {
			_ = command.Process.Kill()
			_ = command.Wait()
			t.Fatalf("helper readiness = %q", line)
		}
	case <-time.After(10 * time.Second):
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal("timed out waiting for journal SIGKILL helper")
	}
	if err := command.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("SIGKILL helper exited successfully")
	}

	recovered, records, err := Open(testConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if len(records) != 1 || string(records[0]) != "fsynced before SIGKILL" {
		t.Fatalf("records after SIGKILL = %q", records)
	}
	if recovered.RecoveryCounter() != 8 {
		t.Fatalf("counter after SIGKILL = %d, want 8", recovered.RecoveryCounter())
	}
}

func TestJournalCompactionSurvivesSIGKILL(t *testing.T) {
	if os.Getenv("SGW_NEXT_CONTROLSTATE_COMPACT_KILL_HELPER") == "1" {
		path := os.Getenv("SGW_NEXT_CONTROLSTATE_COMPACT_KILL_PATH")
		journal, _, err := Open(compactionKillConfig(path))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if err := journal.Start(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		records := make([][]byte, 32)
		for index := range records {
			records[index] = make([]byte, 512<<10)
			records[index][0] = byte(index + 1)
		}
		fmt.Println("ready")
		if err := journal.Compact(records); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		fmt.Println("done")
		for {
			time.Sleep(time.Hour)
		}
	}

	for index, delay := range []time.Duration{0, 2 * time.Millisecond, 20 * time.Millisecond} {
		directory := t.TempDir()
		path := filepath.Join(directory, "compact-kill.wal")
		journal, _, err := Open(compactionKillConfig(path))
		if err != nil {
			t.Fatal(err)
		}
		if err := journal.Start(); err != nil {
			t.Fatal(err)
		}
		if err := journal.Append([]byte("old authoritative state")); err != nil {
			t.Fatal(err)
		}
		if err := journal.Close(); err != nil {
			t.Fatal(err)
		}

		command := exec.Command(os.Args[0], "-test.run=^TestJournalCompactionSurvivesSIGKILL$")
		command.Env = append(os.Environ(),
			"SGW_NEXT_CONTROLSTATE_COMPACT_KILL_HELPER=1",
			"SGW_NEXT_CONTROLSTATE_COMPACT_KILL_PATH="+path,
		)
		stdout, err := command.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		command.Stderr = os.Stderr
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		line, err := bufio.NewReader(stdout).ReadString('\n')
		if err != nil || strings.TrimSpace(line) != "ready" {
			_ = command.Process.Kill()
			_ = command.Wait()
			t.Fatalf("iteration %d helper readiness = %q, error=%v", index, line, err)
		}
		if delay > 0 {
			time.Sleep(delay)
		}
		if err := command.Process.Signal(syscall.SIGKILL); err != nil {
			t.Fatal(err)
		}
		if err := command.Wait(); err == nil {
			t.Fatalf("iteration %d SIGKILL helper exited successfully", index)
		}

		recovered, records, err := Open(compactionKillConfig(path))
		if err != nil {
			t.Fatalf("iteration %d reopen after SIGKILL: %v", index, err)
		}
		if len(records) == 1 {
			if string(records[0]) != "old authoritative state" {
				t.Fatalf("iteration %d recovered unknown old state", index)
			}
		} else if len(records) == 32 {
			for recordIndex, record := range records {
				if len(record) != 512<<10 || record[0] != byte(recordIndex+1) {
					t.Fatalf("iteration %d compacted record %d is invalid", index, recordIndex)
				}
			}
		} else {
			t.Fatalf("iteration %d recovered %d records; want complete old or new state", index, len(records))
		}
		if err := recovered.Close(); err != nil {
			t.Fatal(err)
		}
		matches, err := filepath.Glob(filepath.Join(directory, ".compact-kill.wal.compact-*"))
		if err != nil || len(matches) != 0 {
			t.Fatalf("iteration %d stale compaction files = %v, error=%v", index, matches, err)
		}
	}
}

func compactionKillConfig(path string) Config {
	return Config{
		Path: path, Magic: "LSNCPST1", Identity: []byte("component=compaction-kill-test"),
		MaxBytes: 32 << 20, MaxRecordBytes: 1 << 20, RecoverySeed: 19,
	}
}
