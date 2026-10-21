package agent

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/backoff"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/client"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/collect"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/state"
)

// fakeServer mimics /api/agent/* closely enough to exercise the agent.
type fakeServer struct {
	mu       sync.Mutex
	commands []model.Command
	results  map[string]string
	outputs  map[string]string
	checkins int
	bundle   []byte
	revoked  bool
	acks     int
	ackFail  bool
	files    map[string][]byte // /api/agent/scripts/... downloads
	exitCode map[string]any
	checkin  *model.Report
	offer    string // JSON of the "update" field of check-in responses ("" = none)
	features string // X-CNAPP-Agent-Features of the last check-in
}

func (f *fakeServer) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.URL.Path == "/api/agent/enroll" {
			_, _ = io.WriteString(w, `{"device_id":"dev1","device_secret":"cnd_secret","check_in_interval_seconds":900,"command_poll_seconds":60,"server_time":"`+time.Now().UTC().Format(time.RFC3339)+`","reenrolled":false}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer cnd_secret" {
			w.WriteHeader(401)
			return
		}
		if f.revoked {
			w.WriteHeader(403)
			_, _ = io.WriteString(w, `{"detail":"device revoked"}`)
			return
		}
		now := time.Now().UTC().Format(time.RFC3339)
		switch {
		case r.URL.Path == "/api/agent/checkin":
			var rep model.Report
			if err := json.NewDecoder(r.Body).Decode(&rep); err != nil || rep.Device.Hostname == "" {
				t.Errorf("bad check-in: %v", err)
			}
			f.checkins++
			f.checkin = &rep
			f.features = r.Header.Get("X-CNAPP-Agent-Features")
			upd := ""
			if f.offer != "" {
				upd = `,"update":` + f.offer
			}
			_, _ = io.WriteString(w, `{"device_id":"dev1","server_time":"`+now+`","pending_commands":0,"issues":[]`+upd+`}`)
		case r.URL.Path == "/api/agent/commands":
			b, _ := json.Marshal(model.CommandList{ServerTime: time.Now().UTC(), Commands: f.commands})
			f.commands = nil
			_, _ = w.Write(b)
		case strings.HasSuffix(r.URL.Path, "/result"):
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			id := strings.Split(r.URL.Path, "/")[4]
			f.results[id], _ = body["status"].(string)
			f.outputs[id], _ = body["output"].(string)
			if f.exitCode == nil {
				f.exitCode = map[string]any{}
			}
			f.exitCode[id] = body["exit_code"]
			w.WriteHeader(204)
		case strings.HasSuffix(r.URL.Path, "/ack"):
			f.acks++
			if f.ackFail {
				w.WriteHeader(409)
				_, _ = io.WriteString(w, `{"detail":"already acknowledged"}`)
				return
			}
			_, _ = io.WriteString(w, `{"proceed":true}`)
		case strings.HasPrefix(r.URL.Path, "/api/agent/scripts/"):
			b, ok := f.files[r.URL.Path]
			if !ok {
				w.WriteHeader(404)
				return
			}
			_, _ = w.Write(b)
		case strings.HasSuffix(r.URL.Path, "/logs"):
			f.bundle, _ = io.ReadAll(r.Body)
			w.WriteHeader(201)
		default:
			w.WriteHeader(404)
		}
	})
}

func fakeCollect(context.Context, collect.Options) *model.Report {
	r := &model.Report{Device: model.DeviceInfo{Hostname: "test-host", OSFamily: "macos"}}
	r.Normalize()
	return r
}

func setup(t *testing.T) (*Agent, *fakeServer) {
	t.Helper()
	f := &fakeServer{results: map[string]string{}, outputs: map[string]string{}}
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	p := state.Resolve(t.TempDir())
	if err := state.Save(p, &state.State{ServerURL: srv.URL, DeviceID: "dev1", DeviceSecret: "cnd_secret", InsecureDev: true,
		CheckInIntervalSeconds: 900}); err != nil {
		t.Fatal(err)
	}
	a, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	a.Collect = fakeCollect
	a.Lock = func(context.Context) (string, error) { return "locked (test)", nil }
	a.WipeProbe = readyProbe // never run the real PowerShell probe in unit tests
	return a, f
}

func command(id, typ string, params map[string]any) model.Command {
	return model.Command{ID: id, DeviceID: "dev1", Type: typ, Params: params, Nonce: strings.Repeat("a", 32),
		IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour)}
}

func TestCommandsEndToEnd(t *testing.T) {
	a, f := setup(t)
	restarted := false
	a.Restart = func() { restarted = true }
	expired := command("c-expired", "recheck_posture", nil)
	expired.ExpiresAt = time.Now().Add(-time.Minute)
	other := command("c-other", "lock_device", nil)
	other.DeviceID = "someone-else"
	f.commands = []model.Command{
		command("c-recheck", "recheck_posture", nil),
		command("c-shell", "run_shell", map[string]any{"script": "rm -rf /"}),
		command("c-script", "run_script", map[string]any{"script": "rm -rf /"}),
		command("c-interval", "update_check_in_interval", map[string]any{"interval_seconds": 1800.0}),
		command("c-logs", "collect_logs", nil),
		command("c-lock", "lock_device", nil),
		command("c-restart", "restart_agent", nil),
		expired, other,
	}
	if err := a.PollCommands(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"c-recheck": "succeeded", "c-shell": "rejected", "c-script": "rejected", "c-interval": "succeeded",
		"c-logs": "succeeded", "c-lock": "succeeded", "c-restart": "succeeded", "c-expired": "rejected", "c-other": "rejected"}
	for id, st := range want {
		if f.results[id] != st {
			t.Errorf("%s: %q (%s), want %q", id, f.results[id], f.outputs[id], st)
		}
	}
	if !strings.Contains(f.outputs["c-shell"], "allowlist") {
		t.Errorf("shell output %q", f.outputs["c-shell"])
	}
	if f.checkins != 1 || !restarted || a.interval() != 30*time.Minute {
		t.Errorf("checkins=%d restarted=%v interval=%v", f.checkins, restarted, a.interval())
	}
	// Replay: the same command id is never executed twice, even if re-delivered.
	f.commands = []model.Command{command("c-recheck", "recheck_posture", nil)}
	delete(f.results, "c-recheck")
	_ = a.PollCommands(context.Background())
	if f.checkins != 1 || f.results["c-recheck"] != "" {
		t.Errorf("replayed command executed")
	}
	// Persisted across restarts.
	b, _ := Load(a.Paths)
	if st := b.State(); len(st.ExecutedCommands) != 5 || st.CheckInIntervalSeconds != 1800 {
		t.Errorf("state %+v", st)
	}
	// The log bundle is a gzip tar with the expected files and no secret.
	gz, err := gzip.NewReader(bytes.NewReader(f.bundle))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	names := []string{}
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		names = append(names, h.Name)
		body, _ := io.ReadAll(tr)
		if strings.Contains(string(body), "cnd_secret") {
			t.Errorf("%s leaks the device secret", h.Name)
		}
	}
	if strings.Join(names, ",") != "bundle.json,state.json,inventory.json" {
		t.Errorf("bundle files %v", names)
	}
}

func TestRevokedDeviceBacksOffHourly(t *testing.T) {
	a, f := setup(t)
	f.revoked = true
	err := a.CheckIn(context.Background())
	if !client.IsUnauthorized(err) {
		t.Fatalf("expected unauthorized, got %v", err)
	}
	n, next := a.schedule(err, 0, time.Minute, "check-in")
	if n != 1 || time.Until(next) < 59*time.Minute {
		t.Errorf("revoked device retries too soon: %v", time.Until(next))
	}
}

func TestBackoffOnServerErrors(t *testing.T) {
	a, _ := setup(t)
	a.policy = backoff.Policy{Base: 30 * time.Second, Max: 30 * time.Minute, Rand: func() float64 { return 1 }}
	err := errors.New("connection refused")
	var next time.Time
	n := 0
	for i := 0; i < 3; i++ {
		n, next = a.schedule(err, n, 15*time.Minute, "check-in")
	}
	if n != 3 || time.Until(next) > 2*time.Minute+time.Second || time.Until(next) < 2*time.Minute-time.Second {
		t.Errorf("attempt %d next in %v", n, time.Until(next))
	}
	n, next = a.schedule(nil, n, 15*time.Minute, "check-in")
	if n != 0 || time.Until(next) < 13*time.Minute {
		t.Errorf("success did not reset: %d %v", n, time.Until(next))
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	a, f := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- a.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		n := f.checkins
		f.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
	if f.checkins == 0 {
		t.Fatal("no initial check-in")
	}
}

func TestEnrollSavesState(t *testing.T) {
	f := &fakeServer{results: map[string]string{}, outputs: map[string]string{}}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	p := state.Resolve(t.TempDir())
	if _, err := Enroll(context.Background(), p, EnrollOptions{Server: srv.URL, Token: "cne_x"}); err == nil {
		t.Fatal("http accepted without --insecure-dev")
	}
	resp, err := Enroll(context.Background(), p, EnrollOptions{Server: srv.URL, Token: "cne_x", InsecureDev: true})
	if err != nil || resp.DeviceID != "dev1" {
		t.Fatal(err)
	}
	st, err := state.Load(p)
	if err != nil || st.DeviceSecret != "cnd_secret" || st.CheckInIntervalSeconds != 900 || !st.InsecureDev {
		t.Fatalf("%+v %v", st, err)
	}
}

func TestEnrollWithPrivateCAKeepsACopy(t *testing.T) {
	f := &fakeServer{results: map[string]string{}, outputs: map[string]string{}}
	srv := httptest.NewTLSServer(f.handler(t))
	defer srv.Close()
	src := filepath.Join(t.TempDir(), "corp-root-ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(src, caPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	p := state.Resolve(t.TempDir())
	// Without the CA, enrollment against a privately signed server fails closed.
	if _, err := Enroll(context.Background(), p, EnrollOptions{Server: srv.URL, Token: "cne_x"}); err == nil {
		t.Fatal("enrolled against an untrusted certificate")
	}
	if _, err := Enroll(context.Background(), p, EnrollOptions{Server: srv.URL, Token: "cne_x", CAFile: src}); err != nil {
		t.Fatal(err)
	}
	st, err := state.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.CAFile != p.CAFile() {
		t.Fatalf("CA path persisted as %q, want the copy %q", st.CAFile, p.CAFile())
	}
	if got, _ := os.ReadFile(p.CAFile()); !bytes.Equal(got, caPEM) {
		t.Fatal("CA copy differs from the original")
	}
	// The original may be deleted (e.g. a downloaded file); the agent keeps working.
	if err := os.Remove(src); err != nil {
		t.Fatal(err)
	}
	a, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.CheckIn(context.Background()); err != nil {
		t.Fatalf("check-in with the stored CA: %v", err)
	}
	// Purge removes the CA copy with the credentials.
	if err := state.Remove(p); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p.CAFile()); !os.IsNotExist(err) {
		t.Fatalf("CA copy left behind: %v", err)
	}
}
