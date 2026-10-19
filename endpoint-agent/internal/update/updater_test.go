package update

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/state"
)

type fakeTransport struct {
	files   map[string][]byte
	err     error
	reports []Report
}

func (f *fakeTransport) Fetch(_ context.Context, path string, max int64, w io.Writer) (int64, error) {
	if f.err != nil {
		return 0, f.err
	}
	b, ok := f.files[path]
	if !ok {
		return 0, fmt.Errorf("404 %s", path)
	}
	if int64(len(b)) > max {
		return 0, fmt.Errorf("%w: too large", ErrSizeMismatch)
	}
	n, err := w.Write(b)
	return int64(n), err
}

func (f *fakeTransport) ReportUpdate(_ context.Context, r Report) error {
	f.reports = append(f.reports, r)
	return nil
}

func (f *fakeTransport) statuses() string {
	var s []string
	for _, r := range f.reports {
		s = append(s, r.Status)
	}
	return strings.Join(s, ",")
}

type fakePlatform struct {
	verifyErr, preflightErr, watchdogErr error
	watchdogBinary                       string
	watchdogArgs                         []string
	restarts                             int
}

func (p *fakePlatform) VerifyBinary(string) error { return p.verifyErr }
func (p *fakePlatform) Preflight(_ context.Context, path, want string) error {
	if p.preflightErr != nil {
		return p.preflightErr
	}
	if _, err := os.Stat(path); err != nil {
		return err
	}
	return nil
}
func (p *fakePlatform) StartWatchdog(binary string, args []string) error {
	p.watchdogBinary, p.watchdogArgs = binary, args
	return p.watchdogErr
}
func (p *fakePlatform) RestartService() error { p.restarts++; return nil }

type rig struct {
	u    *Updater
	tr   *fakeTransport
	pf   *fakePlatform
	key  testKey
	bin  string
	now  time.Time
	newB []byte
}

const (
	oldBinary = "old agent binary v1.0.0"
	relID     = "0123456789abcdef0123456789abcdef"
)

func newRig(t *testing.T) *rig {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "cnapp-agent")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if err := os.WriteFile(bin, []byte(oldBinary), 0o755); err != nil {
		t.Fatal(err)
	}
	k := newKey(t)
	r := &rig{tr: &fakeTransport{files: map[string][]byte{}}, pf: &fakePlatform{}, key: k, bin: bin, now: testNow,
		newB: []byte("new agent binary v1.1.0")}
	r.u = &Updater{Keys: []TrustedKey{k.TrustedKey}, Current: "1.0.0", GOOS: "windows", GOARCH: "amd64", BinaryPath: bin,
		Paths:     state.Paths{StateDir: filepath.Join(dir, "state"), LogDir: filepath.Join(dir, "logs"), Custom: true},
		Transport: r.tr, Platform: r.pf, Now: func() time.Time { return r.now }, WatchdogArgs: []string{"--home", dir}}
	r.publish(t, "1.1.0", r.newB, nil)
	return r
}

func (r *rig) publish(t *testing.T, version string, data []byte, mutate func(map[string]any)) {
	m := baseManifest(version, artifactFor("windows", "amd64", data))
	if mutate != nil {
		mutate(m)
	}
	r.tr.files["/api/agent/updates/releases/"+relID+"/manifest"] = sign(t, m, r.key)
	r.tr.files["/api/agent/updates/releases/"+relID+"/artifacts/windows/amd64"] = data
}

func offer(version string) Offer {
	return Offer{ReleaseID: relID, Version: version, ManifestPath: "/api/agent/updates/releases/" + relID + "/manifest",
		ArtifactPath: "/api/agent/updates/releases/" + relID + "/artifacts/windows/amd64", HealthTimeoutSeconds: 120}
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestApplySwapsAndStartsWatchdog(t *testing.T) {
	r := newRig(t)
	err := r.u.Apply(context.Background(), offer("1.1.0"))
	if !errors.Is(err, ErrRestartRequired) {
		t.Fatalf("Apply = %v", err)
	}
	if got := read(t, r.bin); got != string(r.newB) {
		t.Fatalf("binary not replaced: %q", got)
	}
	backup := SidePath(r.bin, "old")
	if got := read(t, backup); got != oldBinary {
		t.Fatalf("backup = %q", got)
	}
	if r.pf.watchdogBinary != backup {
		t.Fatalf("watchdog must run the previous binary, ran %q", r.pf.watchdogBinary)
	}
	if _, err := os.Stat(SidePath(r.bin, "new")); !os.IsNotExist(err) {
		t.Fatal("staging file left behind")
	}
	p := LoadFile(r.u.Paths).Pending
	if p == nil || p.Phase != PhaseSwapped || p.FromVersion != "1.0.0" || p.ToVersion != "1.1.0" ||
		!p.Deadline.Equal(testNow.Add(120*time.Second)) {
		t.Fatalf("pending = %+v", p)
	}
	if got := r.tr.statuses(); got != "downloading,verified,installing" {
		t.Fatalf("reports = %s", got)
	}
	// A repeated offer while the health check runs does nothing.
	if err := r.u.Apply(context.Background(), offer("1.1.0")); err != nil {
		t.Fatal(err)
	}
}

func TestApplyRejectsTamperedArtifactsAndManifests(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, r *rig)
		want  error
	}{
		{"hash mismatch (server swapped the bytes)", func(t *testing.T, r *rig) {
			p := offer("1.1.0").ArtifactPath
			b := append([]byte{}, r.tr.files[p]...)
			b[0] ^= 0xff
			r.tr.files[p] = b
		}, ErrHashMismatch},
		{"size mismatch (truncated)", func(t *testing.T, r *rig) {
			p := offer("1.1.0").ArtifactPath
			r.tr.files[p] = r.tr.files[p][:5]
		}, ErrSizeMismatch},
		{"size mismatch (oversized)", func(t *testing.T, r *rig) {
			p := offer("1.1.0").ArtifactPath
			r.tr.files[p] = append(append([]byte{}, r.tr.files[p]...), "extra"...)
		}, ErrSizeMismatch},
		{"manifest signed by an untrusted key", func(t *testing.T, r *rig) {
			r.tr.files[offer("1.1.0").ManifestPath] = sign(t, baseManifest("1.1.0", artifactFor("windows", "amd64", r.newB)), newKey(t))
		}, ErrNoTrustedKey},
		{"bad signature", func(t *testing.T, r *rig) {
			m := r.tr.files[offer("1.1.0").ManifestPath]
			r.tr.files[offer("1.1.0").ManifestPath] = bytes.Replace(m, []byte(`"sig":"`), []byte(`"sig":"AA`), 1)
		}, ErrBadSignature},
		{"expired manifest", func(t *testing.T, r *rig) {
			r.now = testNow.Add(365 * 24 * time.Hour)
		}, ErrExpired},
		{"downgrade", func(t *testing.T, r *rig) {
			r.u.Current = "2.0.0"
		}, ErrDowngrade},
		{"unknown platform", func(t *testing.T, r *rig) {
			r.u.GOOS = "plan9"
		}, ErrNoArtifact},
		{"offer/manifest version mismatch", func(t *testing.T, r *rig) {
			r.publish(t, "1.2.0", r.newB, nil)
		}, ErrVersionMismatch},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			c.setup(t, r)
			err := r.u.Apply(context.Background(), offer("1.1.0"))
			if !errors.Is(err, c.want) {
				t.Fatalf("Apply = %v, want %v", err, c.want)
			}
			if got := read(t, r.bin); got != oldBinary {
				t.Fatal("binary changed although the update was rejected")
			}
			for _, kind := range []string{"new", "old"} {
				if _, err := os.Stat(SidePath(r.bin, kind)); !os.IsNotExist(err) {
					t.Fatalf("%s file left behind", kind)
				}
			}
			if r.pf.watchdogBinary != "" {
				t.Fatal("watchdog started for a rejected update")
			}
			last := r.tr.reports[len(r.tr.reports)-1]
			if last.Status != StatusRejected || last.Detail == "" {
				t.Fatalf("last report = %+v", last)
			}
			if f := LoadFile(r.u.Paths); len(f.Failed) != 1 || f.Failed[0].ReleaseID != relID {
				t.Fatalf("failed release not recorded: %+v", f)
			}
			// Not retried on the next offer.
			n := len(r.tr.reports)
			if err := r.u.Apply(context.Background(), offer("1.1.0")); err != nil || len(r.tr.reports) != n {
				t.Fatalf("rejected release retried: %v", err)
			}
		})
	}
}

func TestApplyTransientErrorsAreRetried(t *testing.T) {
	r := newRig(t)
	r.tr.err = errors.New("connection reset")
	if err := r.u.Apply(context.Background(), offer("1.1.0")); err == nil {
		t.Fatal("expected an error")
	}
	if f := LoadFile(r.u.Paths); len(f.Failed) != 0 {
		t.Fatal("a network error must not blacklist the release")
	}
	r.tr.err = nil
	if err := r.u.Apply(context.Background(), offer("1.1.0")); !errors.Is(err, ErrRestartRequired) {
		t.Fatalf("retry: %v", err)
	}
}

func TestApplySameVersionIsNoop(t *testing.T) {
	r := newRig(t)
	r.u.Current = "1.1.0"
	if err := r.u.Apply(context.Background(), offer("1.1.0")); err != nil || len(r.tr.reports) != 0 {
		t.Fatalf("err=%v reports=%v", err, r.tr.reports)
	}
}

func TestApplyPlatformChecks(t *testing.T) {
	for _, name := range []string{"code signature", "preflight"} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			if name == "preflight" {
				r.pf.preflightErr = errors.New("reports version 6.6.6")
			} else {
				r.pf.verifyErr = errors.New("not signed")
			}
			if err := r.u.Apply(context.Background(), offer("1.1.0")); err == nil {
				t.Fatal("expected rejection")
			}
			if read(t, r.bin) != oldBinary {
				t.Fatal("binary replaced")
			}
		})
	}
}

func TestApplyUndoesSwapWhenWatchdogCannotStart(t *testing.T) {
	r := newRig(t)
	r.pf.watchdogErr = errors.New("spawn failed")
	if err := r.u.Apply(context.Background(), offer("1.1.0")); err == nil || errors.Is(err, ErrRestartRequired) {
		t.Fatalf("Apply = %v", err)
	}
	if read(t, r.bin) != oldBinary {
		t.Fatal("swap not undone")
	}
	if LoadFile(r.u.Paths).Pending != nil {
		t.Fatal("pending update left behind")
	}
}

func swapped(t *testing.T) *rig {
	r := newRig(t)
	if err := r.u.Apply(context.Background(), offer("1.1.0")); !errors.Is(err, ErrRestartRequired) {
		t.Fatal(err)
	}
	r.tr.reports = nil
	return r
}

func TestHealthyUpdateIsReportedOnce(t *testing.T) {
	r := swapped(t)
	r.u.Current = "1.1.0" // the new binary starts
	if r.u.OnStart() {
		t.Fatal("unexpected self-rollback")
	}
	r.u.MarkHealthy()
	r.u.ReportOutcome(context.Background())
	r.u.ReportOutcome(context.Background())
	if got := r.tr.statuses(); got != "installed" {
		t.Fatalf("reports = %s", got)
	}
	// The watchdog sees the healthy phase and leaves the binary alone.
	if err := r.u.Watchdog(context.Background(), time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if read(t, r.bin) != string(r.newB) || r.pf.restarts != 0 {
		t.Fatal("watchdog touched a healthy update")
	}
}

func TestWatchdogRollsBackUnhealthyUpdate(t *testing.T) {
	r := swapped(t)
	r.now = testNow.Add(121 * time.Second) // past the health deadline
	if err := r.u.Watchdog(context.Background(), time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if read(t, r.bin) != oldBinary {
		t.Fatal("previous binary not restored")
	}
	if read(t, SidePath(r.bin, "failed")) != string(r.newB) {
		t.Fatal("failed binary not kept aside")
	}
	if r.pf.restarts != 1 {
		t.Fatalf("service restarts = %d", r.pf.restarts)
	}
	// The restored old agent reports the rollback and never retries the release.
	r.u.Current = "1.0.0"
	r.u.OnStart()
	r.u.MarkHealthy() // must not mark the rolled-back update healthy
	r.u.ReportOutcome(context.Background())
	if got := r.tr.statuses(); got != "rolled_back" || !strings.Contains(r.tr.reports[0].Detail, "health check failed") {
		t.Fatalf("reports = %+v", r.tr.reports)
	}
	if err := r.u.Apply(context.Background(), offer("1.1.0")); err != nil || len(r.tr.reports) != 1 {
		t.Fatalf("rolled-back release retried: %v %v", err, r.tr.statuses())
	}
}

func TestWatchdogWaitsUntilDeadline(t *testing.T) {
	r := swapped(t)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := r.u.Watchdog(ctx, 5*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Watchdog = %v", err)
	}
	if read(t, r.bin) != string(r.newB) {
		t.Fatal("rolled back before the deadline")
	}
}

func TestCrashLoopSelfRollback(t *testing.T) {
	r := swapped(t)
	r.u.Current = "1.1.0"
	for i := 0; i < MaxStartsBeforeSelfRollback; i++ {
		if r.u.OnStart() {
			t.Fatalf("rolled back after %d starts", i+1)
		}
	}
	if !r.u.OnStart() {
		t.Fatal("expected a self-rollback")
	}
	if read(t, r.bin) != oldBinary {
		t.Fatal("previous binary not restored")
	}
	if p := LoadFile(r.u.Paths).Pending; p.Phase != PhaseRolledBack {
		t.Fatalf("phase = %s", p.Phase)
	}
}

func TestPreviousVersionRunningCountsAsRollback(t *testing.T) {
	r := swapped(t)
	r.u.Current = "1.0.0" // e.g. an MSI repair restored the old binary
	r.u.OnStart()
	r.u.ReportOutcome(context.Background())
	if got := r.tr.statuses(); got != "rolled_back" {
		t.Fatalf("reports = %s", got)
	}
}

func TestOfferOutsideUpdateAPIRejected(t *testing.T) {
	r := newRig(t)
	o := offer("1.1.0")
	o.ArtifactPath = "/api/devices/x"
	if err := r.u.Apply(context.Background(), o); err == nil {
		t.Fatal("expected rejection")
	}
}

func TestHealthTimeoutBounds(t *testing.T) {
	for in, want := range map[int]time.Duration{0: DefaultHealthTimeout, 5: MinHealthTimeout, 999999: MaxHealthTimeout, 300: 5 * time.Minute} {
		if got := HealthTimeout(in); got != want {
			t.Fatalf("HealthTimeout(%d) = %s", in, got)
		}
	}
}

func TestSidePath(t *testing.T) {
	if got := SidePath(`C:\Program Files\CNAPP Agent\cnapp-agent.exe`, "old"); got != `C:\Program Files\CNAPP Agent\cnapp-agent.old.exe` {
		t.Fatal(got)
	}
	if got := SidePath("/usr/local/cnapp-agent/bin/cnapp-agent", "new"); got != "/usr/local/cnapp-agent/bin/cnapp-agent.new" {
		t.Fatal(got)
	}
}

func TestPlatformSignatureParsers(t *testing.T) {
	if err := checkAuthenticode("Valid|CN=Contoso Ltd, O=Contoso", "CN=Contoso Ltd"); err != nil {
		t.Fatal(err)
	}
	if checkAuthenticode("NotSigned|", "") == nil || checkAuthenticode("Valid|CN=Evil", "CN=Contoso Ltd") == nil {
		t.Fatal("bad Authenticode accepted")
	}
	if err := checkCodesign("Identifier=x\nTeamIdentifier=ABCDE12345\n", "ABCDE12345"); err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{"Signature=adhoc\nTeamIdentifier=not set\n", "TeamIdentifier=not set\n", "TeamIdentifier=OTHER\n"} {
		if checkCodesign(out, "ABCDE12345") == nil {
			t.Fatalf("accepted %q", out)
		}
	}
}
