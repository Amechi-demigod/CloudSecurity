package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/update"
)

func TestUpdateFetchAndReport(t *testing.T) {
	var reported update.Report
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer cnd_s" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/api/agent/updates/releases/r1/artifacts/windows/amd64":
			_, _ = io.WriteString(w, "0123456789")
		case "/api/agent/updates/redirect":
			http.Redirect(w, r, "https://elsewhere.example/x", http.StatusFound)
		case "/api/agent/updates/status":
			_ = json.NewDecoder(r.Body).Decode(&reported)
			w.WriteHeader(204)
		case "/api/agent/checkin":
			_, _ = io.WriteString(w, `{"device_id":"d1","server_time":"2026-10-15T10:00:00Z","pending_commands":0,"issues":[],`+
				`"update":{"release_id":"r1","version":"1.2.0","manifest_path":"/api/agent/updates/releases/r1/manifest",`+
				`"artifact_path":"/api/agent/updates/releases/r1/artifacts/windows/amd64","health_timeout_seconds":600,"jitter_seconds":60}}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	c, err := New(srv.URL, "cnd_s", Options{InsecureDev: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var buf bytes.Buffer
	if n, err := c.Fetch(ctx, "/api/agent/updates/releases/r1/artifacts/windows/amd64", 10, &buf); err != nil || n != 10 {
		t.Fatalf("Fetch = %d, %v", n, err)
	}
	buf.Reset()
	if _, err := c.Fetch(ctx, "/api/agent/updates/releases/r1/artifacts/windows/amd64", 9, &buf); !errors.Is(err, update.ErrSizeMismatch) {
		t.Fatalf("oversized download: %v", err)
	}
	for _, bad := range []string{"/api/devices/x", "/api/agent/updates/../devices", "/api/agent/updates/x?y=1", "https://evil/api/agent/updates/x"} {
		if _, err := c.Fetch(ctx, bad, 10, &buf); err == nil || !strings.Contains(err.Error(), "refusing") {
			t.Fatalf("Fetch(%q) = %v", bad, err)
		}
	}
	if _, err := c.Fetch(ctx, "/api/agent/updates/redirect", 10, &buf); err == nil {
		t.Fatal("redirect followed")
	}
	if err := c.ReportUpdate(ctx, update.Report{ReleaseID: "r1", FromVersion: "1.0.0", ToVersion: "1.2.0", Status: "installed"}); err != nil {
		t.Fatal(err)
	}
	if reported.Status != "installed" || reported.ToVersion != "1.2.0" {
		t.Fatalf("reported %+v", reported)
	}
	resp, err := c.CheckIn(ctx, &model.Report{})
	if err != nil || resp.Update == nil || resp.Update.Version != "1.2.0" || resp.Update.JitterSeconds != 60 {
		t.Fatalf("check-in offer: %+v %v", resp, err)
	}
}
