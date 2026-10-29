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

type fakeLostMode func(ctx context.Context) (bool, error)

func (f fakeLostMode) Active(ctx context.Context) (bool, error) { return f(ctx) }

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
	restoreErr     error // makes RestoreLogonRestriction fail, to test rollback-failure handling
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
	if f.restoreErr != nil {
		return f.restoreErr
	}
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
			AdminProbe: fakeAdminProbe(func(context.Context) ([]string, error) { return admins, nil }),
			SessionTerminator: fakeSessionTerminator(func(context.Context, []string) (string, error) {
				// Logged into the backend's call list too, so tests can assert
				// ordering against apply/verify (restrict-before-sign-out).
				backend.calls = append(backend.calls, "signout")
				return "0 sessions", nil
			}),
			Backend:  backend,
			Banner:   banner,
			LostMode: fakeLostMode(func(context.Context) (bool, error) { return false, nil }),
			Now:      func() time.Time { return time.Unix(1_800_000_000, 0) },
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

func TestSuspendRestrictsBeforeSigningOut(t *testing.T) {
	b := goodBackend()
	m, _ := manager(t, b, []string{"Administrator"})
	ctx := context.Background()
	if _, err := m.Suspend(ctx, "INC-1", "cmd1"); err != nil {
		t.Fatal(err)
	}
	idx := map[string]int{}
	for i, c := range b.calls {
		if _, ok := idx[c]; !ok {
			idx[c] = i
		}
	}
	apply, applyOK := idx["apply"]
	verify, verifyOK := idx["verify-blocked"]
	signout, signoutOK := idx["signout"]
	if !applyOK || !verifyOK || !signoutOK {
		t.Fatalf("expected apply/verify-blocked/signout to all appear, got %v", b.calls)
	}
	if !(apply < verify && verify < signout) {
		t.Fatalf("expected restrict (apply) -> verify -> sign-out order, got %v", b.calls)
	}
}

func TestSuspendDoesNotSignOutOnFailedApply(t *testing.T) {
	b := goodBackend()
	b.applyErr = errors.New("LsaRemoveAccountRights: access denied")
	m, _ := manager(t, b, []string{"Administrator"})
	ctx := context.Background()
	if _, err := m.Suspend(ctx, "INC-1", "cmd1"); err == nil {
		t.Fatal("expected Suspend to fail")
	}
	for _, c := range b.calls {
		if c == "signout" {
			t.Fatalf("a failed apply must never sign anyone out, got calls %v", b.calls)
		}
	}
}

func TestSuspendRollbackFailureKeepsRecord(t *testing.T) {
	b := goodBackend()
	b.verifyBlockOK = false
	b.verifyBlockMsg = "BUILTIN\\Administrators would be denied"
	b.restoreErr = errors.New("LsaAddAccountRights: access denied") // the rollback itself fails
	m, _ := manager(t, b, []string{"Administrator"})
	ctx := context.Background()
	_, err := m.Suspend(ctx, "INC-1", "cmd1")
	if err == nil || !strings.Contains(err.Error(), "rollback also failed") {
		t.Fatalf("expected a rollback-failed error, got %v", err)
	}
	rec, lerr := m.Load()
	if lerr != nil || rec == nil {
		t.Fatalf("expected the record to be KEPT after a failed rollback, got %+v %v", rec, lerr)
	}
	if rec.Pending == nil || rec.Pending.LastError == "" {
		t.Fatalf("expected Pending.LastError to record the rollback failure, got %+v", rec.Pending)
	}
}

func TestRestoreKeepsRecordWhenVerificationFails(t *testing.T) {
	b := goodBackend()
	m, _ := manager(t, b, []string{"Administrator"})
	ctx := context.Background()
	if _, err := m.Suspend(ctx, "INC-1", "cmd1"); err != nil {
		t.Fatal(err)
	}
	// RestoreLogonRestriction "succeeds" but leaves the live state wrong, so
	// VerifyStandardSignInWorks reports a mismatch.
	b.cur = "still-restricted"
	b.calls = nil
	// Simulate: RestoreLogonRestriction runs but doesn't actually change cur
	// back (a backend bug), by making restore a no-op via a custom override.
	m.Deps.Backend = &stuckRestoreBackend{fakeBackend: b}
	out, err := m.Restore(ctx)
	if err == nil {
		t.Fatalf("expected an error when restore can't be verified, got output %q", out)
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected a verification-mismatch error, got %v", err)
	}
	rec, lerr := m.Load()
	if lerr != nil || rec == nil {
		t.Fatalf("expected the record to be KEPT when restore can't be verified, got %+v %v", rec, lerr)
	}
}

// stuckRestoreBackend wraps fakeBackend but makes RestoreLogonRestriction a
// no-op (simulating a backend that reports success without actually
// restoring), so VerifyStandardSignInWorks can observe the mismatch.
type stuckRestoreBackend struct{ *fakeBackend }

func (s *stuckRestoreBackend) RestoreLogonRestriction(ctx context.Context, previous json.RawMessage) error {
	s.calls = append(s.calls, "restore")
	return nil // intentionally does not update s.cur
}

func TestSuspendRefusedWhileLostModeActive(t *testing.T) {
	b := goodBackend()
	m, _ := manager(t, b, []string{"Administrator"})
	m.Deps.LostMode = fakeLostMode(func(context.Context) (bool, error) { return true, nil })
	ctx := context.Background()
	_, err := m.Suspend(ctx, "INC-1", "cmd1")
	if err == nil || !strings.Contains(err.Error(), "lost mode") {
		t.Fatalf("expected a clear lost-mode refusal, got %v", err)
	}
	if len(b.calls) != 0 {
		t.Fatalf("expected zero backend calls when refused for lost mode, got %v", b.calls)
	}
	if rec, lerr := m.Load(); lerr != nil || rec != nil {
		t.Fatalf("expected nothing persisted when refused for lost mode, got %+v %v", rec, lerr)
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
