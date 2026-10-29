//go:build windows

// Real-hardware integration test for Windows: creates real local test
// accounts and exercises the real LSA logon-rights restriction via
// Manager.Suspend/Restore against the real winBackend, verifying the actual
// OS effect with LogonUser. Gated by requireHardwareIntegrationCI: it only
// runs in CI, on windows-latest, with an explicit opt-in.
package signin

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/collect"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/state"
)

const (
	testStdUser   = "cnapp-test-std"
	testAdminUser = "cnapp-test-admin"
	// Ephemeral local test accounts only, deleted at the end of the test.
	// Must be <=14 characters: a longer password makes `net user ... /add`
	// print an interactive "computers prior to Windows 2000..." Y/N prompt,
	// which hangs (and then fails) in CI's non-interactive shell.
	testPassword = "Cnapp-Test26!Q"
)

func netUser(args ...string) error {
	out, err := exec.Command("net", append([]string{"user"}, args...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("net user %v: %w: %s", args, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func netLocalGroup(args ...string) error {
	out, err := exec.Command("net", append([]string{"localgroup"}, args...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("net localgroup %v: %w: %s", args, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// procLogonUserW reuses lsa_windows.go's advapi32 lazy-DLL handle (same
// package); LogonUserW isn't wrapped by golang.org/x/sys/windows.
var procLogonUserW = advapi32.NewProc("LogonUserW")

const logon32LogonInteractive = 2

// canLogon reports whether username/password succeeds an interactive logon
// (LOGON32_LOGON_INTERACTIVE) - the real-world effect the logon-rights
// restriction is meant to control.
func canLogon(username, password string) bool {
	u, err := windows.UTF16PtrFromString(username)
	if err != nil {
		return false
	}
	p, err := windows.UTF16PtrFromString(password)
	if err != nil {
		return false
	}
	var tok windows.Token
	r, _, _ := procLogonUserW.Call(uintptr(unsafe.Pointer(u)), 0, uintptr(unsafe.Pointer(p)),
		logon32LogonInteractive, 0, uintptr(unsafe.Pointer(&tok)))
	if r == 0 {
		return false
	}
	_ = tok.Close()
	return true
}

func TestSuspendSignInIntegrationWindows(t *testing.T) {
	requireHardwareIntegrationCI(t)
	ctx := context.Background()

	// Clean slate: remove any stale leftovers from a previously aborted run,
	// then create a fresh standard user and a fresh admin user with known
	// passwords (we cannot LogonUser as the runner's own pre-existing admin
	// account, since we don't know its password).
	_ = netUser(testStdUser, "/delete")
	_ = netUser(testAdminUser, "/delete")
	if err := netUser(testStdUser, testPassword, "/add"); err != nil {
		t.Fatalf("creating standard test user: %v", err)
	}
	t.Cleanup(func() { _ = netUser(testStdUser, "/delete") })
	if err := netUser(testAdminUser, testPassword, "/add"); err != nil {
		t.Fatalf("creating admin test user: %v", err)
	}
	t.Cleanup(func() { _ = netUser(testAdminUser, "/delete") })
	if err := netLocalGroup("Administrators", testAdminUser, "/add"); err != nil {
		t.Fatalf("adding test admin to Administrators: %v", err)
	}

	if !canLogon(testStdUser, testPassword) || !canLogon(testAdminUser, testPassword) {
		t.Fatal("sanity check failed: both test accounts must be able to log on before suspending sign-in")
	}

	// Pre-flight-abort case: a temporary admin-less fixture (never actually
	// empty the real Administrators group on a CI runner - that would risk
	// breaking the runner's own session). This exercises the real pre-flight
	// gate logic against a fake probe, same as the unit tests, just run here
	// too for completeness alongside the real-system checks below.
	abortMgr := New(state.Resolve(t.TempDir()))
	abortMgr.Deps.AdminProbe = fakeAdminProbe(func(context.Context) ([]string, error) { return nil, nil })
	if _, err := abortMgr.Suspend(ctx, "ci-test-abort", "cmd-abort"); err == nil {
		t.Fatal("expected the no-local-admin fixture to refuse to suspend")
	}
	if !canLogon(testStdUser, testPassword) {
		t.Fatal("the aborted (fixture) suspend attempt must not have changed anything")
	}

	// Pre-flight-pass case: the real backend, the real admin probe (which
	// will find testAdminUser plus whatever the runner's own image has).
	m := New(state.Resolve(t.TempDir()))
	admins, err := collect.EnabledLocalAdminNames(ctx)
	if err != nil {
		t.Fatalf("enumerating local admins: %v", err)
	}
	if !contains(admins, testAdminUser) {
		t.Fatalf("expected %s to be found as an enabled local admin, got %v", testAdminUser, admins)
	}

	if _, err := m.Suspend(ctx, "ci-test-suspend", "cmd-suspend"); err != nil {
		t.Fatalf("Suspend: %v", err)
	}
	t.Cleanup(func() {
		if _, err := m.Restore(context.Background()); err != nil {
			t.Logf("cleanup: Restore failed: %v", err)
		}
	})

	if canLogon(testStdUser, testPassword) {
		t.Error("expected the standard test user to be refused interactive logon while suspended")
	}
	if !canLogon(testAdminUser, testPassword) {
		t.Error("expected the admin test user to still be able to log on while suspended")
	}

	// Crash-recovery check: simulate "the agent crashed right after finishing
	// the live LSA changes but before persisting PhaseApplied" by rewriting
	// the on-disk record's phase back to PhaseApplying, then run OnStart
	// against a FRESH Manager pointed at the same real backend/state and
	// confirm it finishes forward correctly (a real LSA read-back), leaving
	// the restriction in effect. This does not kill an actual OS process (not
	// practical inside a single `go test` run); it is still a genuine
	// exercise of OnStart's finish-forward path against the real backend.
	rec, err := m.Load()
	if err != nil || rec == nil {
		t.Fatalf("expected an active record, got %+v %v", rec, err)
	}
	rec.Pending.Phase = PhaseApplying
	if err := m.save(rec); err != nil {
		t.Fatalf("simulating a crash: %v", err)
	}
	m2 := New(m.Paths)
	if !m2.OnStart(ctx) {
		t.Fatal("expected OnStart to act on a PhaseApplying record")
	}
	if r, err := m2.Load(); err != nil || r == nil || r.Pending.Phase != PhaseApplied {
		t.Fatalf("expected OnStart to finish forward to PhaseApplied, got %+v %v", r, err)
	}
	if canLogon(testStdUser, testPassword) {
		t.Error("expected the standard test user to still be refused after crash recovery finished forward")
	}

	if _, err := m.Restore(ctx); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if !canLogon(testStdUser, testPassword) {
		t.Error("expected the standard test user to be able to log on again after restore")
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}
