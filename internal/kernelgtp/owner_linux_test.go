//go:build linux

package kernelgtp

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOwnerLeasePersistsIdentityAndFencesConcurrentProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kernel.owner")
	config := LinkConfig{Name: "lodowner0", OwnershipFile: path}
	first, err := acquireOwnerLease(config)
	if err != nil {
		t.Fatal(err)
	}
	if !isOwnershipAlias(first.alias) {
		t.Fatalf("invalid generated ownership alias %q", first.alias)
	}
	if _, err := acquireOwnerLease(config); !errors.Is(err, ErrOwnerActive) {
		t.Fatalf("second owner lease error = %v, want ErrOwnerActive", err)
	}
	alias := first.alias
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second, err := acquireOwnerLease(config)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if second.alias != alias {
		t.Fatalf("owner identity changed across restart: got %q want %q", second.alias, alias)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("ownership file mode = %04o, want 0600", info.Mode().Perm())
	}
}

func TestOwnerLeaseRejectsMismatchedCorruptAndUnsafeFiles(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "kernel.owner")
	first, err := acquireOwnerLease(LinkConfig{Name: "lodowner0", OwnershipFile: path})
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireOwnerLease(LinkConfig{Name: "lodowner1", OwnershipFile: path}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("mismatched link error = %v, want ErrInvalid", err)
	}

	corrupt := filepath.Join(directory, "corrupt.owner")
	if err := os.WriteFile(corrupt, []byte("not-json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireOwnerLease(LinkConfig{Name: "lodowner0", OwnershipFile: corrupt}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("corrupt record error = %v, want ErrInvalid", err)
	}

	unsafe := filepath.Join(directory, "unsafe.owner")
	if err := os.WriteFile(unsafe, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireOwnerLease(LinkConfig{Name: "lodowner0", OwnershipFile: unsafe}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unsafe mode error = %v, want ErrInvalid", err)
	}

	symlink := filepath.Join(directory, "symlink.owner")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireOwnerLease(LinkConfig{Name: "lodowner0", OwnershipFile: symlink}); err == nil {
		t.Fatal("ownership lease followed a symbolic link")
	}

	unsafeDirectory := filepath.Join(directory, "unsafe-directory")
	if err := os.Mkdir(unsafeDirectory, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafeDirectory, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireOwnerLease(LinkConfig{
		Name: "lodowner0", OwnershipFile: filepath.Join(unsafeDirectory, "kernel.owner"),
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unsafe directory error = %v, want ErrInvalid", err)
	}
}
