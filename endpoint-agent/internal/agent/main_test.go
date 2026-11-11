package agent

import (
	"os"
	"testing"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/commands"
)

// The end-to-end tests here drive desktop commands (lock, wipe, scripts, ...)
// against fake platform backends on every CI OS. On Linux the agent refuses
// those commands; that refusal is tested in internal/commands, so these tests
// run with an OS that has no command restrictions.
func TestMain(m *testing.M) {
	restore := commands.SetGOOSForTest("test")
	code := m.Run()
	restore()
	os.Exit(code)
}
