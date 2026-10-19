package client

import (
	"context"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeCA stores the httptest server's self-signed certificate as a PEM "CA bundle".
func writeCA(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPrivateCATrustedOnlyWithCAFile(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"server_time":"2026-10-15T10:00:00Z","commands":[]}`)
	}))
	defer srv.Close()
	ctx := context.Background()

	// Without the CA the private certificate is rejected (no "ignore TLS errors" mode exists).
	c, err := New(srv.URL, "cnd_s", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Commands(ctx); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("expected a certificate verification error, got %v", err)
	}

	// With --ca-file it is trusted.
	c, err = New(srv.URL, "cnd_s", Options{CAFile: writeCA(t, srv)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Commands(ctx); err != nil {
		t.Fatalf("with CA file: %v", err)
	}
}

func TestCAFileErrors(t *testing.T) {
	if _, err := New("https://cnapp.example", "", Options{CAFile: filepath.Join(t.TempDir(), "missing.pem")}); err == nil {
		t.Fatal("missing CA file accepted")
	}
	bad := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(bad, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New("https://cnapp.example", "", Options{CAFile: bad}); err == nil || !strings.Contains(err.Error(), "no PEM") {
		t.Fatalf("expected 'no PEM certificates', got %v", err)
	}
}
