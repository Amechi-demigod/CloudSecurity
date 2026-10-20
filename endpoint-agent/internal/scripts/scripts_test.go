package scripts

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/update"
)

var now = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

const bundleID = "0123456789abcdef0123456789abcdef"

var script = []byte("Write-Output \"days=$env:CNAPP_PARAM_DAYS\"\n")

func key(t *testing.T) (ed25519.PrivateKey, update.TrustedKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, update.TrustedKey{ID: update.KeyID(pub), Pub: pub}
}

func entry(body []byte) map[string]any {
	sum := sha256.Sum256(body)
	return map[string]any{"name": "clear-temp", "description": "d", "platform": "windows", "interpreter": "powershell",
		"file": "script.ps1", "timeout_seconds": 60, "risk": "medium", "sha256": hex.EncodeToString(sum[:]),
		"size": len(body), "parameters": []any{
			map[string]any{"name": "days", "type": "int", "min": 1, "max": 30, "default": 7},
			map[string]any{"name": "scope", "type": "enum", "values": []string{"system", "users"}},
			map[string]any{"name": "svc", "type": "string", "pattern": "^[A-Za-z]{1,8}$", "required": false},
			map[string]any{"name": "dry", "type": "bool", "default": true},
		}}
}

func manifest(version string, entries ...map[string]any) map[string]any {
	return map[string]any{"schema": 1, "product": Product, "version": version,
		"released_at": now.Add(-time.Hour).Format(time.RFC3339), "expires_at": now.Add(30 * 24 * time.Hour).Format(time.RFC3339),
		"scripts": entries}
}

func sign(t *testing.T, m map[string]any, priv ed25519.PrivateKey, ctx string) []byte {
	payload, _ := json.Marshal(m)
	sig := ed25519.Sign(priv, append([]byte(ctx), payload...))
	env := map[string]any{"payload": base64.StdEncoding.EncodeToString(payload),
		"signatures": []map[string]string{{"key_id": update.KeyID(priv.Public().(ed25519.PublicKey)),
			"sig": base64.StdEncoding.EncodeToString(sig)}}}
	b, _ := json.Marshal(env)
	return b
}

type fakeRunner struct {
	spec RunSpec
	body []byte
	res  RunResult
	runs int
}

func (f *fakeRunner) Run(_ context.Context, s RunSpec) RunResult {
	f.runs++
	f.spec = s
	f.body, _ = os.ReadFile(s.ScriptPath)
	return f.res
}

type env struct {
	files  map[string][]byte
	min    string
	runner *fakeRunner
}

func (e *env) deps(t *testing.T, keys []update.TrustedKey, goos string) Deps {
	return Deps{Keys: keys, GOOS: goos, Now: func() time.Time { return now }, WorkDir: t.TempDir(), Runner: e.runner,
		MinVersion: func() string { return e.min }, SetMinVersion: func(v string) error { e.min = v; return nil },
		Fetch: func(_ context.Context, path string, max int64, w io.Writer) (int64, error) {
			b, ok := e.files[path]
			if !ok {
				return 0, errors.New("404")
			}
			if int64(len(b)) > max {
				return 0, errors.New("too large")
			}
			n, err := w.Write(b)
			return int64(n), err
		}}
}

func command(params map[string]any, sha string) model.Command {
	p := map[string]any{"bundle_id": bundleID, "bundle_version": "1.2.0", "script": "clear-temp", "script_sha256": sha,
		"parameters": params}
	return model.Command{ID: "c1", DeviceID: "dev", Type: "run_script", Params: p, Nonce: strings.Repeat("n", 32),
		IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
}

func setup(t *testing.T, version string, body []byte) (*env, []update.TrustedKey, string, ed25519.PrivateKey) {
	priv, tk := key(t)
	e := entry(script)
	m := manifest(version, e)
	return &env{files: map[string][]byte{
		"/api/agent/scripts/bundles/" + bundleID + "/manifest":           sign(t, m, priv, SignatureContext),
		"/api/agent/scripts/bundles/" + bundleID + "/scripts/clear-temp": body,
	}, runner: &fakeRunner{}}, []update.TrustedKey{tk}, e["sha256"].(string), priv
}

func TestExecuteHappyPath(t *testing.T) {
	e, keys, sha, _ := setup(t, "1.2.0", script)
	e.runner.res = RunResult{ExitCode: 0, Stdout: []byte("days=14\n")}
	o := Execute(context.Background(), command(map[string]any{"days": 14.0, "scope": "users"}, sha), e.deps(t, keys, "windows"))
	if o.Status != "succeeded" || o.ExitCode == nil || *o.ExitCode != 0 || !strings.Contains(o.Output, "days=14") {
		t.Fatalf("%+v", o)
	}
	want := []string{"CNAPP_PARAM_DAYS=14", "CNAPP_PARAM_SCOPE=users", "CNAPP_PARAM_DRY=true"}
	if fmt.Sprint(e.runner.spec.Env) != fmt.Sprint(want) {
		t.Fatalf("env %v", e.runner.spec.Env)
	}
	if !bytes.Equal(e.runner.body, script) || e.runner.spec.Interpreter != "powershell" || e.runner.spec.Timeout != time.Minute {
		t.Fatalf("%+v", e.runner.spec)
	}
	if e.min != "1.2.0" {
		t.Fatalf("min version %q", e.min)
	}
	if _, err := os.Stat(filepath.Dir(e.runner.spec.ScriptPath)); !os.IsNotExist(err) {
		t.Fatal("work directory not removed")
	}
	// Non-zero exit = failed, exit code reported.
	e.runner.res = RunResult{ExitCode: 3, Stderr: []byte("boom")}
	o = Execute(context.Background(), command(map[string]any{"scope": "system"}, sha), e.deps(t, keys, "windows"))
	if o.Status != "failed" || *o.ExitCode != 3 || !strings.Contains(o.Output, "boom") {
		t.Fatalf("%+v", o)
	}
}

func TestExecuteRefusals(t *testing.T) {
	ctx := context.Background()
	good := map[string]any{"scope": "system"}
	t.Run("untrusted key", func(t *testing.T) {
		e, _, sha, _ := setup(t, "1.2.0", script)
		_, other := key(t)
		o := Execute(ctx, command(good, sha), e.deps(t, []update.TrustedKey{other}, "windows"))
		if o.Status != "rejected" || !strings.Contains(o.Output, "not signed by a trusted") || e.runner.runs != 0 {
			t.Fatalf("%+v", o)
		}
	})
	t.Run("no keys compiled in", func(t *testing.T) {
		e, _, sha, _ := setup(t, "1.2.0", script)
		o := Execute(ctx, command(good, sha), e.deps(t, nil, "windows"))
		if o.Status != "rejected" || !strings.Contains(o.Output, "trusts no script-signing keys") {
			t.Fatalf("%+v", o)
		}
	})
	t.Run("agent-update signature context", func(t *testing.T) {
		e, keys, sha, priv := setup(t, "1.2.0", script)
		e.files["/api/agent/scripts/bundles/"+bundleID+"/manifest"] = sign(t, manifest("1.2.0", entry(script)), priv, update.SignatureContext)
		if o := Execute(ctx, command(good, sha), e.deps(t, keys, "windows")); o.Status != "rejected" || !strings.Contains(o.Output, "signature is invalid") {
			t.Fatalf("%+v", o)
		}
	})
	t.Run("tampered script", func(t *testing.T) {
		e, keys, sha, _ := setup(t, "1.2.0", append([]byte("Remove-Item C:\\ -Recurse\n"), script...)[:len(script)])
		if o := Execute(ctx, command(good, sha), e.deps(t, keys, "windows")); o.Status != "rejected" || !strings.Contains(o.Output, "tampered") || e.runner.runs != 0 {
			t.Fatalf("%+v", o)
		}
	})
	t.Run("hash claimed by the server differs", func(t *testing.T) {
		e, keys, _, _ := setup(t, "1.2.0", script)
		if o := Execute(ctx, command(good, strings.Repeat("a", 64)), e.deps(t, keys, "windows")); o.Status != "rejected" {
			t.Fatalf("%+v", o)
		}
	})
	t.Run("rollback", func(t *testing.T) {
		e, keys, sha, _ := setup(t, "1.2.0", script)
		e.min = "1.3.0"
		if o := Execute(ctx, command(good, sha), e.deps(t, keys, "windows")); o.Status != "rejected" || !strings.Contains(o.Output, "anti-rollback") {
			t.Fatalf("%+v", o)
		}
	})
	t.Run("version mismatch", func(t *testing.T) {
		e, keys, sha, _ := setup(t, "1.2.1", script)
		if o := Execute(ctx, command(good, sha), e.deps(t, keys, "windows")); o.Status != "rejected" {
			t.Fatalf("%+v", o)
		}
	})
	t.Run("expired", func(t *testing.T) {
		e, keys, sha, priv := setup(t, "1.2.0", script)
		m := manifest("1.2.0", entry(script))
		m["released_at"], m["expires_at"] = now.Add(-48*time.Hour).Format(time.RFC3339), now.Add(-time.Hour).Format(time.RFC3339)
		e.files["/api/agent/scripts/bundles/"+bundleID+"/manifest"] = sign(t, m, priv, SignatureContext)
		if o := Execute(ctx, command(good, sha), e.deps(t, keys, "windows")); o.Status != "rejected" || !strings.Contains(o.Output, "expired") {
			t.Fatalf("%+v", o)
		}
	})
	t.Run("wrong platform", func(t *testing.T) {
		e, keys, sha, _ := setup(t, "1.2.0", script)
		if o := Execute(ctx, command(good, sha), e.deps(t, keys, "darwin")); o.Status != "rejected" || !strings.Contains(o.Output, "for windows") {
			t.Fatalf("%+v", o)
		}
	})
	for name, params := range map[string]map[string]any{
		"missing required": {},
		"enum":             {"scope": "C:\\"},
		"int range":        {"scope": "system", "days": 31.0},
		"int injection":    {"scope": "system", "days": "7; whoami"},
		"string pattern":   {"scope": "system", "svc": "Spooler; calc"},
		"control chars":    {"scope": "system", "svc": "a\nb"},
		"bool":             {"scope": "system", "dry": "yes"},
		"unknown":          {"scope": "system", "cmd": "whoami"},
	} {
		t.Run("param "+name, func(t *testing.T) {
			e, keys, sha, _ := setup(t, "1.2.0", script)
			if o := Execute(ctx, command(params, sha), e.deps(t, keys, "windows")); o.Status != "rejected" || e.runner.runs != 0 {
				t.Fatalf("%+v", o)
			}
		})
	}
	t.Run("bad command shape", func(t *testing.T) {
		c := command(good, strings.Repeat("a", 64))
		c.Params["bundle_id"] = "../../etc"
		if err := ValidateCommand(c); err == nil {
			t.Fatal("accepted")
		}
	})
}

func TestOutputTruncation(t *testing.T) {
	e := &Entry{Name: "x"}
	m := &Manifest{Version: "1.0.0", KeyID: "k"}
	big := bytes.Repeat([]byte("a"), 60000)
	o := format(e, m, RunResult{ExitCode: 0, Stdout: big, Stderr: big}, time.Second)
	if len(o.Output) > MaxResultBytes || !strings.Contains(o.Output, "[output truncated]") {
		t.Fatalf("len %d", len(o.Output))
	}
	o = format(e, m, RunResult{TimedOut: true, ExitCode: -1}, time.Second)
	if o.Status != "failed" || !strings.Contains(o.Output, "TIMED OUT") {
		t.Fatalf("%+v", o)
	}
}

// The repository's device-scripts must also pass the agent's validation
// (the Python side checks the same files in backend/tests/test_device_scripts.py).
func TestRepoScriptsValidate(t *testing.T) {
	dirs, err := filepath.Glob("../../../device-scripts/*/manifest.json")
	if err != nil || len(dirs) == 0 {
		t.Skip("device-scripts not found")
	}
	for _, mf := range dirs {
		b, _ := os.ReadFile(mf)
		var e Entry
		if err := json.Unmarshal(b, &e); err != nil {
			t.Fatal(mf, err)
		}
		body, err := os.ReadFile(filepath.Join(filepath.Dir(mf), e.File))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(body)
		e.SHA256, e.Size = hex.EncodeToString(sum[:]), int64(len(body))
		if err := e.validate(); err != nil {
			t.Errorf("%s: %v", mf, err)
		}
		if _, err := e.ValidateParams(map[string]any{}); err != nil && !strings.Contains(err.Error(), "required") {
			t.Errorf("%s defaults: %v", mf, err)
		}
	}
}

func TestOSRunner(t *testing.T) {
	dir := t.TempDir()
	var kind, body, slow string
	switch runtime.GOOS {
	case "windows":
		kind, body, slow = "powershell", "Write-Output \"v=$env:CNAPP_PARAM_V\"; [Console]::Error.WriteLine('err'); exit 4", "Start-Sleep -Seconds 30"
	default:
		if _, err := os.Stat("/bin/bash"); err != nil {
			t.Skip("no bash")
		}
		kind, body, slow = "bash", "echo \"v=$CNAPP_PARAM_V\"; echo err >&2; exit 4", "sleep 30 & sleep 30"
	}
	ext := map[string]string{"powershell": ".ps1", "bash": ".sh"}[kind]
	p := filepath.Join(dir, "s"+ext)
	_ = os.WriteFile(p, []byte(body), 0o600)
	t.Setenv("CNAPP_PARAM_V", "leaked") // inherited CNAPP_* variables are dropped
	r := OSRunner{}.Run(context.Background(), RunSpec{Interpreter: kind, ScriptPath: p, Dir: dir,
		Env: []string{"CNAPP_PARAM_V=a b;c"}, Timeout: time.Minute})
	if r.Err != nil || r.ExitCode != 4 || !strings.Contains(string(r.Stdout), "v=a b;c") || !strings.Contains(string(r.Stderr), "err") {
		t.Fatalf("%+v stdout=%q stderr=%q", r, r.Stdout, r.Stderr)
	}
	_ = os.WriteFile(p, []byte(slow), 0o600)
	start := time.Now()
	r = OSRunner{}.Run(context.Background(), RunSpec{Interpreter: kind, ScriptPath: p, Dir: dir, Timeout: 2 * time.Second})
	if !r.TimedOut || time.Since(start) > 20*time.Second {
		t.Fatalf("%+v after %s", r, time.Since(start))
	}
}
