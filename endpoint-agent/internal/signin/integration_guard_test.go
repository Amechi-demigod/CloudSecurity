package signin

import (
	"os"
	"testing"
)

// requireHardwareIntegrationCI gates every real-hardware integration test in
// this package: it must refuse to run anywhere except GitHub-hosted CI. Both
// CI=true and the explicit opt-in RUN_HARDWARE_INTEGRATION_TESTS=1 are
// required, so a developer running `go test ./...` locally never creates real
// local accounts, grants/restricts real LSA rights, or edits a real
// com.apple.access_loginwindow group on their own machine.
func requireHardwareIntegrationCI(t *testing.T) {
	t.Helper()
	if os.Getenv("CI") != "true" || os.Getenv("RUN_HARDWARE_INTEGRATION_TESTS") != "1" {
		t.Skip("real-hardware integration test: set CI=true and RUN_HARDWARE_INTEGRATION_TESTS=1 to run " +
			"(refuses to run anywhere else, including a developer's machine)")
	}
}
