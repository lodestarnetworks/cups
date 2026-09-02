package policyapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadTokenFileRequiresOwnerOnlyRegularSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy-token")
	if err := os.WriteFile(path, testToken, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadTokenFile(path)
	if err != nil || string(loaded) != string(testToken) {
		t.Fatalf("loaded token = %q, %v", loaded, err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTokenFile(path); err == nil || !strings.Contains(err.Error(), "outside its owner") {
		t.Fatalf("shared token permissions error = %v", err)
	}
	symlink := filepath.Join(t.TempDir(), "policy-token-link")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTokenFile(symlink); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlink token error = %v", err)
	}
}

func TestLoadMTLSConfigRequiresCompleteFiles(t *testing.T) {
	if config, err := LoadMTLSConfig("", "", ""); err != nil || config != nil {
		t.Fatalf("disabled mTLS = %#v, %v", config, err)
	}
	if _, err := LoadMTLSConfig("server.crt", "", "ca.crt"); err == nil {
		t.Fatal("partial mTLS configuration was accepted")
	}
}
