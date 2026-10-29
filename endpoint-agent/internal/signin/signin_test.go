package signin

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/lostmode"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/state"
)

// fakeAdminProbe is a function-adapter fake, mirroring internal/wipe's execFunc.
type fakeAdminProbe func(ctx context.Context) ([]string, error)

func (f fakeAdminProbe) EnabledLocalAdmins(ctx context.Context) ([]string, error) { return f(ctx) }

type fakeLAPSProbe func(ctx context.Context) (LAPSStatus, error)

func (f fakeLAPSProbe) Status(ctx context.Context) (LAPSStatus, error) { return f(ctx) }

type fakeSessionTerminator func(ctx context.Context, admins []string) (string, error)

func (f fakeSessionTerminator) SignOutNonAdmins(ctx context.Context, admins []string) (string, error) {
	return f(ctx, admins)
}

// fakeBackend implements Backend in memory, tracking call order so tests can
// assert "snapshot persisted before any live change" and verification/
// rollback behavior, the same way internal/wipe's fakeWMI tracks calls.
type fakeBackend struct {
	calls []string
	cur   string // the "live" restriction state, just a label for assertions

	applyErr       error
	verifyBlockOK  bool
	verifyBlockMsg string
	verifyBlockErr error
}

func (f *fakeBackend) Name() string { return "fake backend" }

func (f *fakeBackend) CaptureLogonRestriction(ctx context.Context) (json.RawMessage, error) {
	f.calls = append(f.calls, "capture:"+f.cur)
	return json.Marshal(f.cur)
}

func (f *fakeBackend) ApplyLogonRestriction(ctx context.Context, adminNames []string, previous json.RawMessage) (string, error) {
	f.calls = append(f.calls, "apply")
	if f.applyErr != nil {
		return "", f.applyErr
	}
	f.cur = "restricted"
	return "restricted to admins", nil
}

func (f *fakeBackend) RestoreLogonRestriction(ctx context.Context, previous json.RawMessage) error {
	f.calls = append(f.calls, "restore")
	var prev string
	if err := json.Unmarshal(previous, &prev); err != nil {
		return err
	}
	f.cur = prev
	return nil
}

func (f *fakeBackend) VerifyStandardSignInBlocked(ctx context.Context, adminNames []string) (bool, string, error) {
	f.calls = append(f.calls, "verify-blocked")
	if f.verifyBlockErr != nil {
		return false, "", f.verifyBlockErr
	}
	return f.verifyBlockOK, f.verifyBlockMsg, nil
}

func (f *fakeBackend) VerifyStandardSignInWorks(ctx context.Context, previous json.RawMessage) (bool, string, error) {
	f.calls = append(f.calls, "verify-works")
	var prev string
	if err := json.Unmarshal(previous, &prev); err != nil {
		return false, "", err
	}
	return f.cur == prev, "matches", nil
}

type fakeBanner struct {
	cur      lostmode.Notice
	restored []lostmode.Notice
}

func (f *fakeBanner) Name() string                                 { return "fake banner" }
func (f *fakeBanner) Get(context.Context) (lostmode.Notice, error) { return f.cur, nil }
func (f *fakeBanner) Set(_ context.Context, n lostmode.Notice) error {
	f.cur = n
	return nil
}
func (f *fakeBanner) Restore(_ context.Context, n lostmode.Notice) error {
	f.restored = append(f.restored, n)
	f.cur = n
	return nil
}

func manager(t *testing.T, backend *fakeBackend, admins []string) (*Manager, *fakeBanner) {
	t.Helper()
	banner := &fakeBanner{}
	m := &Manager{
		Paths: state.Resolve(t.TempDir()),
		Deps: Deps{
			AdminProbe:        fakeAdminProbe(func(context.Context) ([]string, error) { return admins, nil }),
			SessionTerminator: fakeSessionTerminator(func(context.Context, []string) (string, error) { return "0 sessions", nil }),
			Backend:           backend,
			Banner:            banner,
			Now:               func() time.Time { return time.Unix(1_800_000_000, 0) },
		},
	}
	return m, banner
}

func goodBackend() *fakeBackend {
	return &fakeBackend{cur: "open", verifyBlockOK: true, verifyBlockMsg: "ok"}
}

func TestPreflightRefusesWithNoLocalAdmin(t *testing.T) {
	m, _ := manager(t, goodBackend(), nil)
	ctx := context.Background()
	if _, err := m.Preflight(ctx); !errors.Is(err, ErrNoLocalAdminPresent) {
		t.Fatalf("got %v, want ErrNoLocalAdminPresent", err)
	}
	if _, err := m.Suspend(ctx, "INC-1", "cmd1"); !errors.Is(err, ErrNoLocalAdminPresent) {
		t.Fatalf("Suspend: got %v, want ErrNoLocalAdminPresent", err)
	}
	if rec, err := m.Load(); err != nil || rec != nil {
		t.Fatalf("expected nothing persisted, got %+v %v", rec, err)
	}
}

func TestPreflightProbeErrorIsDistinctFromNoAdmin(t *testing.T) {
	m, _ := manager(t, goodBackend(), nil)
	m.Deps.AdminProbe = fakeAdminProbe(func(context.Context) ([]string, error) {
		return nil, errors.New("WMI timeout")
	})
	ctx := context.Background()
	_, err := m.Preflight(ctx)
	if err == nil || errors.Is(err, ErrNoLocalAdminPresent) {
		t.Fatalf("got %v, want a distinct probe error, not ErrNoLocalAdminPresent", err)
	}
	if !strings.Contains(err.Error(), "WMI timeout") {
		t.Fatalf("expected the underlying error to be wrapped, got %v", err)
	}
	if rec, lerr := m.Load(); lerr != nil || rec != nil {
		t.Fatalf("expected nothing persisted, got %+v %v", rec, lerr)
	}
}

func TestSnapshotWrittenBeforeAnyLiveChange(t *testing.T) {
	b := goodBackend()
	m, _ := manager(t, b, []string{"Administrator"})
	ctx := context.Background()
	if _, err := m.Suspend(ctx, "INC-1", "cmd1"); err != nil {
		t.Fatal(err)
	}
	// capture must come before apply, and a record must exist on disk by then.
	captureIdx, applyIdx := -1, -1
	for i, c := range b.calls {
		if c == "capture:open" && captureIdx == -1 {
			captureIdx = i
		}
		if c == "apply" && applyIdx == -1 {
			applyIdx = i
		}
	}
	if captureIdx == -1 || applyIdx == -1 || captureIdx > applyIdx {
		t.Fatalf("expected capture before apply, got call order %v", b.calls)
	}
	rec, err := m.Load()
	if err != nil || rec == nil || !rec.Active {
		t.Fatalf("expected an active record after suspend, got %+v %v", rec, err)
	}
}

func TestAdminAccessNeverRemovedSafetyCheck(t *testing.T) {
	b := goodBackend()
	b.verifyBlockOK = false
	b.verifyBlockMsg = "BUILTIN\\Administrators would be denied"
	m, _ := manager(t, b, []string{"Administrator"})
	ctx := context.Background()
	if _, err := m.Suspend(ctx, "INC-1", "cmd1"); err == nil || !strings.Contains(err.Error(), "safety check failed") {
		t.Fatalf("expected a safety-check failure, got %v", err)
	}
	// Must have rolled back (restore called) and left nothing persisted.
	found := false
	for _, c := range b.calls {
		if c == "restore" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a rollback restore call, got %v", b.calls)
	}
	if rec, err := m.Load(); err != nil || rec != nil {
		t.Fatalf("expected nothing left behind after a failed safety check, got %+v %v", rec, err)
	}
	if b.cur != "open" {
		t.Fatalf("expected the backend to be reverted to its original state, got %q", b.cur)
	}
}

func TestRestoreMatchesSnapshotExactly(t *testing.T) {
	b := goodBackend()
	m, banner := manager(t, b, []string{"Administrator"})
	ctx := context.Background()
	if _, err := m.Suspend(ctx, "INC-1", "cmd1"); err != nil {
		t.Fatal(err)
	}
	if b.cur != "restricted" {
		t.Fatalf("expected the backend to be restricted, got %q", b.cur)
	}
	if _, err := m.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	if b.cur != "open" {
		t.Fatalf("expected the backend restored to its pre-suspend state, got %q", b.cur)
	}
	if len(banner.restored) != 1 {
		t.Fatalf("expected exactly one banner restore, got %d", len(banner.restored))
	}
	if rec, err := m.Load(); err != nil || rec != nil {
		t.Fatalf("expected the record to be gone after restore, got %+v %v", rec, err)
	}
}

func TestIdempotentRepeatSuspendKeepsOriginalPrevious(t *testing.T) {
	b := goodBackend()
	m, _ := manager(t, b, []string{"Administrator"})
	ctx := context.Background()
	if _, err := m.Suspend(ctx, "INC-1", "cmd1"); err != nil {
		t.Fatal(err)
	}
	first, err := m.Load()
	if err != nil || first == nil {
		t.Fatalf("expected a record after the first suspend, got %+v %v", first, err)
	}
	firstPrevious := first.Previous

	captureCallsBefore := 0
	for _, c := range b.calls {
		if c == "capture:open" {
			captureCallsBefore++
		}
	}

	if _, err := m.Suspend(ctx, "INC-2", "cmd2"); err != nil {
		t.Fatal(err)
	}
	second, err := m.Load()
	if err != nil || second == nil {
		t.Fatalf("expected a record after the second suspend, got %+v %v", second, err)
	}
	if string(second.Previous.LogonRestriction) != string(firstPrevious.LogonRestriction) {
		t.Fatalf("Previous changed on a repeat suspend: %s != %s", second.Previous.LogonRestriction, firstPrevious.LogonRestriction)
	}
	if second.IncidentID != "INC-2" || second.CommandID != "cmd2" {
		t.Fatalf("expected the incident reference to update in place, got %+v", second)
	}
	captureCallsAfter := 0
	for _, c := range b.calls {
		if c == "capture:open" {
			captureCallsAfter++
		}
	}
	if captureCallsAfter != captureCallsBefore {
		t.Fatalf("expected no re-capture on a repeat suspend, got %d new capture call(s)", captureCallsAfter-captureCallsBefore)
	}
}

func TestIdempotentRepeatRestoreIsNoop(t *testing.T) {
	b := goodBackend()
	m, _ := manager(t, b, []string{"Administrator"})
	ctx := context.Background()
	out, err := m.Restore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "not suspended") {
		t.Fatalf("expected a not-suspended message, got %q", out)
	}
	if len(b.calls) != 0 {
		t.Fatalf("expected zero backend calls on a no-op restore, got %v", b.calls)
	}
}
