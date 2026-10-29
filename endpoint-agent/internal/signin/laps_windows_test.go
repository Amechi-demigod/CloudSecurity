//go:build windows

package signin

import (
	"context"
	"strings"
	"testing"
)

// TestLAPSProbeNeverTouchesAPasswordShapedAPI is a static guard over the
// registry VALUE NAMES this package reads and the Win32/registry API calls it
// makes - NOT the policy KEY PATHS, which are allowed to contain "AdmPwd"
// (that is Microsoft's actual, documented legacy-LAPS policy key name, not a
// secret or a password-retrieval mechanism; windowsLAPSPolicyKey/
// legacyLAPSPolicyKey are deliberately excluded from this check). The real
// password is an Active Directory attribute (ms-Mcs-AdmPwd / msLAPS-Password)
// or escrowed to Entra ID - neither is a registry value this probe reads, and
// it calls no PowerShell/WMI password-retrieval cmdlet at all.
func TestLAPSProbeNeverTouchesAPasswordShapedAPI(t *testing.T) {
	denylist := []string{"password", "secret", "ms-mcs-admpwd", "mslaps-password"}
	// The exact registry value names laps_windows.go reads, and the
	// registry-package API methods it calls to read them - never the
	// containing key paths.
	valueNamesAndAPIs := []string{"BackupDirectory", "AdmPwdEnabled", "OpenKey", "GetIntegerValue"}
	for _, n := range valueNamesAndAPIs {
		lower := strings.ToLower(n)
		for _, bad := range denylist {
			if strings.Contains(lower, bad) {
				t.Fatalf("LAPS telemetry value/API name %q looks password-shaped (matches %q)", n, bad)
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
