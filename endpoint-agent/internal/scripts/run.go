package scripts

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/update"
)

// Output limits: each stream is captured up to MaxStreamBytes; the reported
// result (exit code + stdout + stderr) is truncated to MaxResultBytes.
const (
	MaxStreamBytes = 64 << 10
	MaxResultBytes = 15000
)

var (
	idRe   = regexp.MustCompile(`^[0-9a-f]{32}$`)
	hashRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ValidateCommand checks the shape of run_script parameters (the allowlist step).
func ValidateCommand(c model.Command) error {
	p := c.Params
	if id, _ := p["bundle_id"].(string); !idRe.MatchString(id) {
		return errors.New("bundle_id must be 32 hex characters")
	}
	if v, _ := p["bundle_version"].(string); v == "" {
		return errors.New("bundle_version is required")
	}
	if n, _ := p["script"].(string); !nameRe.MatchString(n) {
		return errors.New("script name is invalid")
	}
	if h, _ := p["script_sha256"].(string); !hashRe.MatchString(h) {
		return errors.New("script_sha256 must be 64 lowercase hex characters")
	}
	if v, ok := p["parameters"]; ok && v != nil {
		if _, ok := v.(map[string]any); !ok {
			return errors.New("parameters must be an object")
		}
	}
	return nil
}

// RunSpec is what the Runner executes.
type RunSpec struct {
	Interpreter string // powershell | zsh | bash
	ScriptPath  string
	Dir         string
	Env         []string // CNAPP_PARAM_* only; the runner adds the base environment
	Timeout     time.Duration
}

// RunResult of a script.
type RunResult struct {
	ExitCode  int
	Stdout    []byte
	Stderr    []byte
	Truncated bool
	TimedOut  bool
	Err       error // could not start / wait failed (not a non-zero exit)
}

// Runner executes interpreters (OSRunner in production, a fake in tests).
type Runner interface {
	Run(ctx context.Context, s RunSpec) RunResult
}

// Deps of Execute.
type Deps struct {
	Keys          []update.TrustedKey
	GOOS          string
	Fetch         func(ctx context.Context, path string, max int64, w io.Writer) (int64, error)
	MinVersion    func() string
	SetMinVersion func(v string) error
	WorkDir       string // protected directory (SYSTEM/Administrators or root only)
	Now           func() time.Time
	Runner        Runner
}

// Outcome of a run_script command.
type Outcome struct {
	Status   string // succeeded | failed | rejected
	Output   string
	ExitCode *int
}

func rejected(format string, a ...any) Outcome {
	return Outcome{Status: "rejected", Output: fmt.Sprintf(format, a...)}
}

// Platform maps GOOS to the manifest platform name.
func Platform(goos string) string {
	if goos == "darwin" {
		return "macos"
	}
	return goos
}

// Execute verifies and runs one run_script command. Every check happens here,
// right before running: signature (compiled-in keys), expiry, anti-rollback,
// platform, script hash and size, and the parameters against the signed schema.
func Execute(ctx context.Context, c model.Command, d Deps) Outcome {
	if err := ValidateCommand(c); err != nil {
		return rejected("%v", err)
	}
	bundleID := c.Params["bundle_id"].(string)
	name := c.Params["script"].(string)
	var env bytes.Buffer
	if _, err := d.Fetch(ctx, "/api/agent/scripts/bundles/"+bundleID+"/manifest", MaxManifestBytes, &env); err != nil {
		return Outcome{Status: "failed", Output: "downloading the signed manifest: " + err.Error()}
	}
	m, err := Verify(env.Bytes(), d.Keys, d.Now())
	if err != nil {
		return rejected("%v", err)
	}
	if want, _ := c.Params["bundle_version"].(string); want != m.Version {
		return rejected("signed bundle version %s does not match the command (%s)", m.Version, want)
	}
	if min := d.MinVersion(); min != "" {
		if cmp, err := update.CompareVersions(m.Version, min); err == nil && cmp < 0 {
			return rejected("script bundle %s is older than %s, which this agent already used (anti-rollback)", m.Version, min)
		}
	}
	var e *Entry
	for i := range m.Scripts {
		if m.Scripts[i].Name == name {
			e = &m.Scripts[i]
		}
	}
	if e == nil {
		return rejected("script %q is not in signed bundle %s", name, m.Version)
	}
	if want, _ := c.Params["script_sha256"].(string); want != e.SHA256 {
		return rejected("the command's script hash does not match the signed manifest")
	}
	if e.Platform != Platform(d.GOOS) {
		return rejected("script %s is for %s, this device runs %s", e.Name, e.Platform, Platform(d.GOOS))
	}
	values, _ := c.Params["parameters"].(map[string]any)
	paramEnv, err := e.ValidateParams(values)
	if err != nil {
		return rejected("%v", err)
	}
	var body bytes.Buffer
	if _, err := d.Fetch(ctx, "/api/agent/scripts/bundles/"+bundleID+"/scripts/"+name, e.Size, &body); err != nil {
		return Outcome{Status: "failed", Output: "downloading the script: " + err.Error()}
	}
	sum := sha256.Sum256(body.Bytes())
	if int64(body.Len()) != e.Size || hex.EncodeToString(sum[:]) != e.SHA256 {
		return rejected("downloaded script does not match the SHA-256 in the signed manifest (tampered)")
	}
	if cmp, err := update.CompareVersions(m.Version, d.MinVersion()); d.MinVersion() == "" || (err == nil && cmp > 0) {
		if err := d.SetMinVersion(m.Version); err != nil {
			return Outcome{Status: "failed", Output: "cannot persist the script bundle version: " + err.Error()}
		}
	}
	dir, err := os.MkdirTemp(d.WorkDir, "script-")
	if err != nil {
		return Outcome{Status: "failed", Output: "creating the work directory: " + err.Error()}
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, e.File)
	if err := os.WriteFile(path, body.Bytes(), 0o600); err != nil {
		return Outcome{Status: "failed", Output: "writing the script: " + err.Error()}
	}
	timeout := time.Duration(e.TimeoutSeconds) * time.Second
	r := d.Runner.Run(ctx, RunSpec{Interpreter: e.Interpreter, ScriptPath: path, Dir: dir, Env: paramEnv, Timeout: timeout})
	return format(e, m, r, timeout)
}

func format(e *Entry, m *Manifest, r RunResult, timeout time.Duration) Outcome {
	if r.Err != nil && !r.TimedOut {
		return Outcome{Status: "failed", Output: fmt.Sprintf("script %s (bundle %s) could not run: %v", e.Name, m.Version, r.Err)}
	}
	code := r.ExitCode
	var b strings.Builder
	fmt.Fprintf(&b, "script %s (bundle %s, signed by %s)\n", e.Name, m.Version, m.KeyID)
	if r.TimedOut {
		fmt.Fprintf(&b, "TIMED OUT after %s (process tree killed)\n", timeout)
	}
	fmt.Fprintf(&b, "exit code: %d\n", code)
	stdout, stderr := string(r.Stdout), string(r.Stderr)
	budget := MaxResultBytes - b.Len() - 80
	half := budget / 2
	if len(stderr) < half {
		half = budget - len(stderr)
	}
	trunc := r.Truncated
	if len(stdout) > half {
		stdout, trunc = stdout[:half], true
	}
	if rest := budget - len(stdout); len(stderr) > rest {
		stderr, trunc = stderr[:max(rest, 0)], true
	}
	fmt.Fprintf(&b, "--- stdout ---\n%s\n--- stderr ---\n%s", strings.TrimRight(stdout, "\r\n"), strings.TrimRight(stderr, "\r\n"))
	if trunc {
		b.WriteString("\n[output truncated]")
	}
	status := "succeeded"
	if code != 0 || r.TimedOut {
		status = "failed"
	}
	return Outcome{Status: status, Output: b.String(), ExitCode: &code}
}

// capped keeps the first n bytes written and remembers whether more came.
type capped struct {
	buf       bytes.Buffer
	n         int
	truncated bool
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.n - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
			c.truncated = true
		} else {
			c.buf.Write(p)
		}
	} else if len(p) > 0 {
		c.truncated = true
	}
	return len(p), nil
}
