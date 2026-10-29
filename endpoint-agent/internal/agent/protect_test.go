package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/lostmode"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/scripts"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/state"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/update"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/wipe"
)

type fakeWMI struct{ calls []string }

func (f *fakeWMI) Invoke(_ context.Context, m string) (string, error) {
	f.calls = append(f.calls, m)
	return "ReturnValue=0", nil
}

func readyProbe(_ context.Context, optIn bool) wipe.Readiness {
	t := true
	r := wipe.Readiness{OptIn: optIn, Supported: true, WinREEnabled: &t, MDMBridge: &t,
		Methods: []string{"doWipeMethod", "doWipeProtectedMethod"}}
	r.Finish()
	return r
}

type memNotice struct{ n lostmode.Notice }

func (m *memNotice) Name() string                                       { return "mem" }
func (m *memNotice) Get(context.Context) (lostmode.Notice, error)       { return m.n, nil }
func (m *memNotice) Set(_ context.Context, n lostmode.Notice) error     { m.n = n; return nil }
func (m *memNotice) Restore(_ context.Context, n lostmode.Notice) error { m.n = n; return nil }

func wipeCmd(id string) model.Command {
	return command(id, "wipe_device", map[string]any{"mode": "protected", "hostname": "test-host"})
}

func TestWipeEndToEndRequiresOptInAndAck(t *testing.T) {
	a, f := setup(t)
	w := &fakeWMI{}
	a.GOOS, a.WipeExec, a.WipeProbe = "windows", w, readyProbe
	ctx := context.Background()
	// Report readiness (and learn the hostname) at check-in.
	if err := a.CheckIn(ctx); err != nil {
		t.Fatal(err)
	}
	rw := f.checkin.Posture["remote_wipe"]
	if rw.Data["opt_in"] != false || rw.Data["ready"] != false || !strings.Contains(rw.Detail, "not opted in") {
		t.Fatalf("%+v", rw)
	}
	// Not opted in: rejected, no ack, no WMI call.
	f.commands = []model.Command{wipeCmd("w1")}
	_ = a.PollCommands(ctx)
	if f.results["w1"] != "rejected" || f.acks != 0 || len(w.calls) != 0 {
		t.Fatalf("%v acks=%d calls=%v", f.results, f.acks, w.calls)
	}
	// Opt in locally (what the MSI does), then the wipe acks and runs once.
	if err := state.SavePolicy(a.Paths, state.Policy{AllowWipe: true, Source: "test"}); err != nil {
		t.Fatal(err)
	}
	f.commands = []model.Command{wipeCmd("w2")}
	_ = a.PollCommands(ctx)
	if f.results["w2"] != "succeeded" || f.acks != 1 || len(w.calls) != 1 || w.calls[0] != "doWipeProtectedMethod" {
		t.Fatalf("%v acks=%d calls=%v out=%q", f.results, f.acks, w.calls, f.outputs["w2"])
	}
	// Replay of the same command id: ignored.
	f.commands = []model.Command{wipeCmd("w2")}
	_ = a.PollCommands(ctx)
	if f.acks != 1 || len(w.calls) != 1 {
		t.Fatal("replayed wipe executed")
	}
	// Server refuses the ack: no wipe.
	f.ackFail = true
	f.commands = []model.Command{wipeCmd("w3")}
	_ = a.PollCommands(ctx)
	if f.results["w3"] != "failed" || len(w.calls) != 1 {
		t.Fatalf("%v calls=%v", f.results, w.calls)
	}
	// A wipe for another hostname is refused.
	f.ackFail = false
	c := wipeCmd("w4")
	c.Params["hostname"] = "OTHER-PC"
	f.commands = []model.Command{c}
	_ = a.PollCommands(ctx)
	if f.results["w4"] != "rejected" || len(w.calls) != 1 {
		t.Fatalf("%v", f.results)
	}
}

func TestLostModeEndToEnd(t *testing.T) {
	a, f := setup(t)
	mem := &memNotice{n: lostmode.Notice{Text: "Authorized use only", TextSet: true}}
	a.LostMode.Backend = mem
	locks := 0
	a.Lock = func(context.Context) (string, error) { locks++; return "locked", nil }
	ctx := context.Background()
	f.commands = []model.Command{command("l1", "enable_lost_mode", map[string]any{"message": "Lost laptop", "phone": "+234 800"})}
	_ = a.PollCommands(ctx)
	if f.results["l1"] != "succeeded" || locks != 1 || !strings.Contains(mem.n.Text, "+234 800") {
		t.Fatalf("%v %q locks=%d", f.results, mem.n.Text, locks)
	}
	_ = a.CheckIn(ctx)
	if f.checkin.Posture["lost_mode"].Data["active"] != true {
		t.Fatalf("%+v", f.checkin.Posture["lost_mode"])
	}
	a.nextRelock = time.Now().Add(-time.Second)
	a.maybeRelock(ctx)
	if locks != 2 {
		t.Fatalf("relock: %d", locks)
	}
	f.commands = []model.Command{command("l2", "disable_lost_mode", nil)}
	_ = a.PollCommands(ctx)
	if f.results["l2"] != "succeeded" || mem.n.Text != "Authorized use only" {
		t.Fatalf("%v %+v", f.results, mem.n)
	}
	_ = a.CheckIn(ctx)
	if f.checkin.Posture["lost_mode"].Data["active"] != false {
		t.Fatal("still active")
	}
}

type fakeScriptRunner struct{ spec scripts.RunSpec }

func (r *fakeScriptRunner) Run(_ context.Context, s scripts.RunSpec) scripts.RunResult {
	r.spec = s
	return scripts.RunResult{ExitCode: 2, Stdout: []byte("hello")}
}

func TestRunScriptEndToEnd(t *testing.T) {
	a, f := setup(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	a.ScriptKeys = []update.TrustedKey{{ID: update.KeyID(pub), Pub: pub}}
	a.GOOS = "darwin"
	runner := &fakeScriptRunner{}
	a.ScriptRunner = runner
	body := []byte("print hi\n")
	sum := sha256.Sum256(body)
	sha := hex.EncodeToString(sum[:])
	m := map[string]any{"schema": 1, "product": scripts.Product, "version": "2.0.0",
		"released_at": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		"expires_at":  time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		"scripts": []any{map[string]any{"name": "mac-hello", "description": "d", "platform": "macos", "interpreter": "zsh",
			"file": "script.zsh", "timeout_seconds": 30, "risk": "low", "sha256": sha, "size": len(body), "parameters": []any{}}}}
	payload, _ := json.Marshal(m)
	sig := ed25519.Sign(priv, append([]byte(scripts.SignatureContext), payload...))
	env, _ := json.Marshal(map[string]any{"payload": base64.StdEncoding.EncodeToString(payload),
		"signatures": []any{map[string]string{"key_id": update.KeyID(pub), "sig": base64.StdEncoding.EncodeToString(sig)}}})
	bid := strings.Repeat("ab", 16)
	f.files = map[string][]byte{"/api/agent/scripts/bundles/" + bid + "/manifest": env,
		"/api/agent/scripts/bundles/" + bid + "/scripts/mac-hello": body}
	f.commands = []model.Command{command("s1", "run_script", map[string]any{"bundle_id": bid, "bundle_version": "2.0.0",
		"script": "mac-hello", "script_sha256": sha, "parameters": map[string]any{}})}
	_ = a.PollCommands(context.Background())
	if f.results["s1"] != "failed" || f.exitCode["s1"] != 2.0 || !strings.Contains(f.outputs["s1"], "hello") {
		t.Fatalf("%v %v %q", f.results, f.exitCode, f.outputs["s1"])
	}
	if runner.spec.Interpreter != "zsh" || a.State().ScriptBundleVersion != "2.0.0" {
		t.Fatalf("%+v %q", runner.spec, a.State().ScriptBundleVersion)
	}
}

// Fakes for signin.Deps - internal/agent must NEVER exercise isolate_host/
// restore_host against the real platform backend in a test, or `go test
// ./...` would mutate real OS logon rights / groups on whatever machine runs it.

type fakeSigninBackend struct{ cur string }

func (f *fakeSigninBackend) Name() string { return "fake" }
func (f *fakeSigninBackend) CaptureLogonRestriction(context.Context) (json.RawMessage, error) {
	return json.Marshal(f.cur)
}
func (f *fakeSigninBackend) ApplyLogonRestriction(context.Context, []string, json.RawMessage) (string, error) {
	f.cur = "restricted"
	return "restricted", nil
}
func (f *fakeSigninBackend) RestoreLogonRestriction(_ context.Context, previous json.RawMessage) error {
	var prev string
	if err := json.Unmarshal(previous, &prev); err != nil {
		return err
	}
	f.cur = prev
	return nil
}
func (f *fakeSigninBackend) VerifyStandardSignInBlocked(context.Context, []string) (bool, string, error) {
	return true, "blocked", nil
}
func (f *fakeSigninBackend) VerifyStandardSignInWorks(_ context.Context, previous json.RawMessage) (bool, string, error) {
	var prev string
	if err := json.Unmarshal(previous, &prev); err != nil {
		return false, "", err
	}
	return f.cur == prev, "matches", nil
}

type fakeSigninAdmins []string

func (f fakeSigninAdmins) EnabledLocalAdmins(context.Context) ([]string, error) {
	return []string(f), nil
}

type fakeSigninSessions struct{}

func (fakeSigninSessions) SignOutNonAdmins(context.Context, []string) (string, error) {
	return "0 sessions", nil
}

type fakeSigninLostMode bool

func (f fakeSigninLostMode) Active(context.Context) (bool, error) { return bool(f), nil }

func TestSuspendSignInEndToEnd(t *testing.T) {
	a, f := setup(t)
	backend := &fakeSigninBackend{cur: "open"}
	a.Signin.Deps.Backend = backend
	a.Signin.Deps.AdminProbe = fakeSigninAdmins{"Administrator"}
	a.Signin.Deps.SessionTerminator = fakeSigninSessions{}
	a.Signin.Deps.Banner = &memNotice{}
	a.Signin.Deps.LostMode = fakeSigninLostMode(false)
	ctx := context.Background()

	f.commands = []model.Command{command("i1", "isolate_host", map[string]any{"incident_id": "INC-1"})}
	_ = a.PollCommands(ctx)
	if f.results["i1"] != "succeeded" {
		t.Fatalf("%v out=%q", f.results, f.outputs["i1"])
	}
	rec, err := a.Signin.Load()
	if err != nil || rec == nil || !rec.Active || rec.IncidentID != "INC-1" {
		t.Fatalf("expected an active record, got %+v %v", rec, err)
	}

	_ = a.CheckIn(ctx)
	iso := f.checkin.Posture["isolation"]
	if iso.Data["active"] != true {
		t.Fatalf("%+v", iso)
	}

	f.commands = []model.Command{command("i2", "restore_host", nil)}
	_ = a.PollCommands(ctx)
	if f.results["i2"] != "succeeded" {
		t.Fatalf("%v out=%q", f.results, f.outputs["i2"])
	}
	if rec2, err := a.Signin.Load(); err != nil || rec2 != nil {
		t.Fatalf("expected no record after restore, got %+v %v", rec2, err)
	}
	_ = a.CheckIn(ctx)
	if f.checkin.Posture["isolation"].Data["active"] != false {
		t.Fatal("still active")
	}

	// No local admin -> rejected, nothing changed.
	a.Signin.Deps.AdminProbe = fakeSigninAdmins(nil)
	f.commands = []model.Command{command("i3", "isolate_host", nil)}
	_ = a.PollCommands(ctx)
	if f.results["i3"] != "rejected" || !strings.Contains(f.outputs["i3"], "ERR_NO_LOCAL_ADMIN_PRESENT") {
		t.Fatalf("%v out=%q", f.results, f.outputs["i3"])
	}

	// Lost mode active -> rejected.
	a.Signin.Deps.AdminProbe = fakeSigninAdmins{"Administrator"}
	a.Signin.Deps.LostMode = fakeSigninLostMode(true)
	f.commands = []model.Command{command("i4", "isolate_host", nil)}
	_ = a.PollCommands(ctx)
	if f.results["i4"] != "rejected" || !strings.Contains(f.outputs["i4"], "lost mode") {
		t.Fatalf("%v out=%q", f.results, f.outputs["i4"])
	}
}

func TestIsolateRestoreHostUnavailableWhenSigninNil(t *testing.T) {
	a, f := setup(t)
	a.Signin = nil
	ctx := context.Background()
	f.commands = []model.Command{command("i1", "isolate_host", nil)}
	_ = a.PollCommands(ctx)
	if f.results["i1"] != "rejected" {
		t.Fatalf("%v", f.results)
	}
	f.commands = []model.Command{command("i2", "restore_host", nil)}
	_ = a.PollCommands(ctx)
	if f.results["i2"] != "rejected" {
		t.Fatalf("%v", f.results)
	}
}

func TestMaybeReenforceSignin(t *testing.T) {
	a, _ := setup(t)
	backend := &fakeSigninBackend{cur: "open"}
	a.Signin.Deps.Backend = backend
	a.Signin.Deps.AdminProbe = fakeSigninAdmins{"Administrator"}
	a.Signin.Deps.SessionTerminator = fakeSigninSessions{}
	a.Signin.Deps.Banner = &memNotice{}
	a.Signin.Deps.LostMode = fakeSigninLostMode(false)
	ctx := context.Background()
	if _, err := a.Signin.Suspend(ctx, "INC-1", "cmd1"); err != nil {
		t.Fatal(err)
	}
	a.nextSigninReenforce = time.Now().Add(-time.Second)
	a.maybeReenforceSignin(ctx)
	if !time.Now().Before(a.nextSigninReenforce) {
		t.Fatal("expected nextSigninReenforce to be rescheduled")
	}
}
