package agent

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/backoff"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/state"
)

const goodToken = "cne_installer-token-0123456789abcdef"

// enrollServer is an HTTPS server with a private certificate that accepts goodToken.
type enrollServer struct {
	mu       sync.Mutex
	srv      *httptest.Server
	attempts int
	accept   bool
}

func newEnrollServer(t *testing.T) *enrollServer {
	e := &enrollServer{accept: true}
	e.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		defer e.mu.Unlock()
		if r.URL.Path != "/api/agent/enroll" {
			w.WriteHeader(404)
			return
		}
		e.attempts++
		var body struct {
			Token string `json:"token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if !e.accept || body.Token != goodToken {
			w.WriteHeader(401)
			_, _ = io.WriteString(w, `{"detail":"invalid, expired, revoked or used-up enrollment token"}`)
			return
		}
		_, _ = io.WriteString(w, `{"device_id":"dev-auto","device_secret":"cnd_auto","check_in_interval_seconds":900,`+
			`"command_poll_seconds":60,"server_time":"`+time.Now().UTC().Format(time.RFC3339)+`","reenrolled":false}`)
	}))
	t.Cleanup(e.srv.Close)
	return e
}

func (e *enrollServer) caPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.srv.Certificate().Raw}))
}

func fastTimings(t *testing.T) {
	old := []time.Duration{ConfigPollInterval, TokenRejectedRetry}
	oldPolicy := EnrollBackoff
	ConfigPollInterval, TokenRejectedRetry = 20*time.Millisecond, 50*time.Millisecond
	EnrollBackoff = backoff.Policy{Base: 10 * time.Millisecond, Max: 20 * time.Millisecond}
	t.Cleanup(func() {
		ConfigPollInterval, TokenRejectedRetry = old[0], old[1]
		EnrollBackoff = oldPolicy
	})
}

func TestAutoEnrollFromConfigDeletesToken(t *testing.T) {
	fastTimings(t)
	e := newEnrollServer(t)
	p := state.Resolve(t.TempDir())
	if err := state.SaveEnrollConfig(p, &state.EnrollConfig{ServerURL: e.srv.URL, Token: goodToken, CAPEM: e.caPEM()}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := AutoEnroll(ctx, p); err != nil {
		t.Fatal(err)
	}
	st, err := state.Load(p)
	if err != nil || st.DeviceID != "dev-auto" || st.CAFile != p.CAFile() {
		t.Fatalf("state %+v %v", st, err)
	}
	if _, err := os.Stat(p.EnrollFile()); !os.IsNotExist(err) {
		t.Fatalf("enroll.json (token) still on disk: %v", err)
	}
	// The private CA from the config is kept, so the enrolled agent can talk to the server.
	a, err := Load(p)
	if err != nil || a.State().ServerURL != e.srv.URL {
		t.Fatalf("load after auto-enroll: %v", err)
	}
}

func TestAutoEnrollIsIdempotentWhenEnrolled(t *testing.T) {
	fastTimings(t)
	e := newEnrollServer(t)
	p := state.Resolve(t.TempDir())
	if err := state.Save(p, &state.State{ServerURL: "https://old.example", DeviceID: "dev-old", DeviceSecret: "cnd_old"}); err != nil {
		t.Fatal(err)
	}
	// A re-installed package drops a new config next to an existing enrollment.
	if err := state.SaveEnrollConfig(p, &state.EnrollConfig{ServerURL: e.srv.URL, Token: goodToken}); err != nil {
		t.Fatal(err)
	}
	if err := AutoEnroll(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	st, _ := state.Load(p)
	if st.DeviceID != "dev-old" || e.attempts != 0 {
		t.Fatalf("re-enrolled an enrolled device: %+v attempts=%d", st, e.attempts)
	}
	if _, err := os.Stat(p.EnrollFile()); !os.IsNotExist(err) {
		t.Fatal("token kept on an enrolled device")
	}
}

func TestAutoEnrollRetriesRejectedTokenThenSucceeds(t *testing.T) {
	fastTimings(t)
	e := newEnrollServer(t)
	e.accept = false
	p := state.Resolve(t.TempDir())
	if err := state.SaveEnrollConfig(p, &state.EnrollConfig{ServerURL: e.srv.URL, Token: goodToken, CAPEM: e.caPEM()}); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(300 * time.Millisecond)
		e.mu.Lock()
		e.accept = true // e.g. the admin raised the device limit
		e.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := AutoEnroll(ctx, p); err != nil {
		t.Fatal(err)
	}
	if e.attempts < 2 {
		t.Fatalf("expected retries, got %d attempts", e.attempts)
	}
	if _, err := os.Stat(p.EnrollFile()); !os.IsNotExist(err) {
		t.Fatal("token not deleted")
	}
}

func TestAutoEnrollWaitsForConfigAndStopsOnCancel(t *testing.T) {
	fastTimings(t)
	p := state.Resolve(t.TempDir())
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if err := AutoEnroll(ctx, p); err != context.DeadlineExceeded {
		t.Fatalf("expected the wait to end with the context, got %v", err)
	}
	// A config dropped while waiting is picked up.
	e := newEnrollServer(t)
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = state.SaveEnrollConfig(p, &state.EnrollConfig{ServerURL: e.srv.URL, Token: goodToken, CAPEM: e.caPEM()})
	}()
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Minute)
	defer cancel2()
	if err := AutoEnroll(ctx2, p); err != nil {
		t.Fatal(err)
	}
	if _, err := state.Load(p); err != nil {
		t.Fatal(err)
	}
}

func TestAutoEnrollWithoutCARejectsPrivateCertificate(t *testing.T) {
	fastTimings(t)
	e := newEnrollServer(t)
	p := state.Resolve(t.TempDir())
	if err := state.SaveEnrollConfig(p, &state.EnrollConfig{ServerURL: e.srv.URL, Token: goodToken}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := AutoEnroll(ctx, p); err == nil {
		t.Fatal("enrolled against an untrusted certificate")
	}
	if _, err := os.Stat(p.EnrollFile()); err != nil {
		t.Fatal("config must be kept for the next attempt")
	}
	if e.attempts != 0 {
		t.Fatal("request reached the handler despite TLS failure")
	}
}
