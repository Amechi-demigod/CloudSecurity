package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
)

// TestResponseReadIsCapped confirms do() never buffers more than maxResponse
// bytes of a response body. The handler streams a well-formed JSON commands
// list padded well past the cap with filler entries; if it were read in full
// it would unmarshal successfully, so a truncated-JSON error here proves the
// client stopped reading at the cap rather than buffering the whole body.
func TestResponseReadIsCapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/commands" {
			return
		}
		// Each filler command is a bit over 100 bytes; this comfortably
		// exceeds maxResponse (1 MiB) while remaining valid JSON overall.
		var b strings.Builder
		b.WriteString(`{"server_time":"2026-10-15T10:00:00Z","commands":[`)
		for i := 0; i < 20000; i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(`{"id":"c","device_id":"d","type":"recheck_posture","params":{},` +
				`"nonce":"0123456789abcdef","issued_at":"2026-10-15T10:00:00Z","expires_at":"2026-10-16T10:00:00Z"}`)
		}
		b.WriteString(`]}`)
		if b.Len() <= maxResponse {
			t.Fatalf("test fixture too small to exceed maxResponse: %d bytes", b.Len())
		}
		_, _ = io.WriteString(w, b.String())
	}))
	defer srv.Close()

	c, _ := New(srv.URL, "cnd_s", Options{InsecureDev: true})
	if _, err := c.Commands(context.Background()); err == nil {
		t.Fatal("expected the oversized response to fail to unmarshal once truncated at the cap")
	}
}

func TestRefusesPlainHTTPWithoutInsecureDev(t *testing.T) {
	if _, err := New("http://example.com", "", Options{}); err == nil {
		t.Fatal("expected http to be refused")
	}
	if _, err := New("http://example.com", "", Options{InsecureDev: true}); err != nil {
		t.Fatal(err)
	}
}

func TestEnrollAndAuthHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/agent/enroll":
			if r.Header.Get("Authorization") != "" {
				t.Error("enroll must not send a credential")
			}
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["token"] != "cne_tok" {
				t.Errorf("token %v", body["token"])
			}
			_, _ = io.WriteString(w, `{"device_id":"d1","device_secret":"cnd_s","check_in_interval_seconds":900,"command_poll_seconds":60,"server_time":"2026-10-15T10:00:00Z","reenrolled":false}`)
		case "/api/agent/commands":
			if r.Header.Get("Authorization") != "Bearer cnd_s" {
				w.WriteHeader(401)
				_, _ = io.WriteString(w, `{"detail":"missing or invalid device credential"}`)
				return
			}
			_, _ = io.WriteString(w, `{"server_time":"2026-10-15T10:00:00Z","commands":[{"id":"c1","device_id":"d1","type":"recheck_posture","params":{},"nonce":"n","issued_at":"2026-10-15T10:00:00Z","expires_at":"2026-10-16T10:00:00Z"}]}`)
		case "/api/agent/checkin":
			b, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(b), `"disks":[]`) {
				t.Errorf("report not normalized: %s", b)
			}
			_, _ = io.WriteString(w, `{"device_id":"d1","server_time":"2026-10-15T10:00:00Z","pending_commands":0,"issues":[]}`)
		case "/api/agent/commands/c1/logs":
			if r.Header.Get("X-Command-Nonce") != "n" || r.Header.Get("Content-Type") != "application/gzip" {
				t.Error("log upload headers")
			}
			w.WriteHeader(201)
		case "/redirect":
			http.Redirect(w, r, "https://elsewhere.example/", http.StatusFound)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	c, _ := New(srv.URL, "", Options{InsecureDev: true})
	er, err := c.Enroll(ctx, "cne_tok", EnrollDevice{Hostname: "h", OSFamily: "macos"})
	if err != nil || er.DeviceSecret != "cnd_s" {
		t.Fatalf("%v %v", er, err)
	}
	if _, err := c.Commands(ctx); !IsUnauthorized(err) {
		t.Fatalf("expected 401, got %v", err)
	}
	if !strings.Contains(err2str(c.Commands(ctx)), "invalid device credential") {
		t.Fatal("detail not parsed")
	}
	c, _ = New(srv.URL, er.DeviceSecret, Options{InsecureDev: true})
	cl, err := c.Commands(ctx)
	if err != nil || len(cl.Commands) != 1 || cl.Commands[0].Type != "recheck_posture" {
		t.Fatalf("%v %v", cl, err)
	}
	if _, err := c.CheckIn(ctx, &model.Report{Device: model.DeviceInfo{Hostname: "h", OSFamily: "macos"}}); err != nil {
		t.Fatal(err)
	}
	if err := c.UploadLogs(ctx, cl.Commands[0], []byte{0x1f, 0x8b}); err != nil {
		t.Fatal(err)
	}
	if err := c.do(ctx, "GET", "/redirect", "", nil, nil, nil); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("redirect followed: %v", err)
	}
}

func err2str(_ any, err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
