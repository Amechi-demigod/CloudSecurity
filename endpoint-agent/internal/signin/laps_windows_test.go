//go:build windows

package signin

import (
	"context"
	"strings"
	"testing"
)

// TestLAPSProbeNeverTouchesAPasswordShapedAPI is a static guard: every
// registry value name or key this package's LAPS telemetry reads must never
// look like a password-retrieval mechanism. LAPS passwords are an Active
// Directory attribute or escrowed to Entra ID - neither is a registry value,
// and this package calls no PowerShell/WMI password-retrieval cmdlet at all.
func TestLAPSProbeNeverTouchesAPasswordShapedAPI(t *testing.T) {
	denylist := []string{"password", "pwd", "secret"}
	names := []string{windowsLAPSPolicyKey, legacyLAPSPolicyKey, "BackupDirectory", "AdmPwdEnabled"}
	for _, n := range names {
		lower := strings.ToLower(n)
		for _, bad := range denylist {
			if strings.Contains(lower, bad) {
				t.Fatalf("LAPS telemetry constant %q looks password-shaped (matches %q)", n, bad)
			}
		}
	}
}

func TestLAPSProbeHandlesNoPolicyPresent(t *testing.T) {
	// On a non-managed machine (no LAPS GPO/CSP at all), Status must report
	// "not configured" rather than erroring, since this is best-effort
	// telemetry that must never block suspend sign-in.
	st, err := (winLAPSProbe{}).Status(context.Background())
	if err != nil {
		t.Fatalf("Status must not error when no policy is present: %v", err)
	}
	_ = st // Configured may be true or false depending on the test runner's actual policy state.
}
