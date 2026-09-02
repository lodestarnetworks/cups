package policyapi

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
)

// LoadTokenFile reads an owner-only bearer token. Secrets embedded directly in
// YAML or passed on a command line are deliberately unsupported.
func LoadTokenFile(path string) ([]byte, error) {
	if err := requirePrivateRegularFile(path, "policy authentication token"); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open policy authentication token: %w", err)
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, 1025))
	if err != nil {
		return nil, fmt.Errorf("read policy authentication token: %w", err)
	}
	if len(value) > 1024 {
		return nil, errors.New("policy authentication token exceeds 1024 bytes")
	}
	return value, nil
}

// LoadMTLSConfig builds a TLS 1.3 server configuration that requires a client
// certificate chaining to the explicitly configured policy-controller CA.
func LoadMTLSConfig(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	if certFile == "" && keyFile == "" && clientCAFile == "" {
		return nil, nil
	}
	if certFile == "" || keyFile == "" || clientCAFile == "" {
		return nil, errors.New("policy mTLS requires certificate, key, and client CA files")
	}
	if err := requirePrivateRegularFile(keyFile, "policy TLS private key"); err != nil {
		return nil, err
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load policy TLS key pair: %w", err)
	}
	caPEM, err := os.ReadFile(clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("read policy client CA: %w", err)
	}
	if len(caPEM) == 0 || len(caPEM) > 1<<20 {
		return nil, errors.New("policy client CA must contain 1..1048576 bytes")
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("policy client CA contains no valid certificates")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    clientCAs, ClientAuth: tls.RequireAndVerifyClientCert,
	}, nil
}

func requirePrivateRegularFile(path, description string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", description, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s must be a regular file, not a symlink or device", description)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s permissions %04o expose it outside its owner", description, info.Mode().Perm())
	}
	return nil
}
