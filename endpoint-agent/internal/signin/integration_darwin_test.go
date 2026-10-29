//go:build darwin

// Real-hardware integration test for macOS: exercises the real
// com.apple.access_loginwindow group via Manager.Suspend/Restore against the
// real macBackend. It deliberately verifies the access_loginwindow group
// state specifically - NEVER PAM or authorizationdb, since neither is
// touched by this feature. Gated by requireHardwareIntegrationCI: it only
// runs in CI, on macos-latest, with an explicit opt-in.
package signin

import (
	"context"
	"testing"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/collect"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/state"
)

func TestSuspendSignInIntegrationMacOS(t *testing.T) {
	requireHardwareIntegrationCI(t)
	ctx := context.Background()

	admins, err := collect.AdminGroupMembers(ctx)
	if err != nil || len(admins) == 0 {
		t.Fatalf("expected at least one local admin on the runner, got %v %v", admins, err)
	}

	baseline, err := captureAccessLoginwindow(ctx)
	if err != nil {
		t.Fatalf("capturing the baseline: %v", err)
	}

	m := New(state.Resolve(t.TempDir()))
	if _, err := m.Suspend(ctx, "ci-test-suspend", "cmd-suspend"); err != nil {
		t.Fatalf("Suspend: %v", err)
	}
	t.Cleanup(func() {
		if _, err := m.Restore(context.Background()); err != nil {
			t.Logf("cleanup: Restore failed: %v", err)
		}
	})

	// Assert the group now exists with the local admin group as its sole
	// member - never check PAM or authorizationdb here, neither is touched.
	suspended, err := captureAccessLoginwindow(ctx)
	if err != nil {
		t.Fatalf("capturing the suspended state: %v", err)
	}
	if !suspended.GroupExisted {
		t.Fatal("expected com.apple.access_loginwindow to exist while suspended")
	}
	if len(suspended.UserMembers) != 0 {
		t.Fatalf("expected no direct user members, got %v", suspended.UserMembers)
	}
	if len(suspended.Members) != 1 || !suspended.Members[0].IsGroup || suspended.Members[0].Name != localAdminGroup {
		t.Fatalf("expected the sole member to be the local %s group, got %+v", localAdminGroup, suspended.Members)
	}

	if _, err := m.Restore(ctx); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	// Restore must put the group back EXACTLY: gone entirely if it didn't
	// exist before, or member-for-member identical if it did.
	restored, err := captureAccessLoginwindow(ctx)
	if err != nil {
		t.Fatalf("capturing the restored state: %v", err)
	}
	if restored.GroupExisted != baseline.GroupExisted {
		t.Fatalf("expected GroupExisted to match the baseline exactly: baseline=%v restored=%v",
			baseline.GroupExisted, restored.GroupExisted)
	}
	if baseline.GroupExisted {
		if !sameStringSet(restored.UserMembers, baseline.UserMembers) || !sameMemberSet(restored.Members, baseline.Members) {
			t.Fatalf("expected membership to match the baseline exactly, got baseline=%+v restored=%+v", baseline, restored)
		}
	}

	// What this test cannot verify headlessly: an actual interactive
	// login-window refusal, since CI runners have no GUI session. See the
	// manual hardware checklist in the PR description / docs.
}
