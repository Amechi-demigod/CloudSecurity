package main

import (
	"os/exec"
	"strings"
	"testing"
)

// The collector must not contain anything that acts on a machine: its import
// graph (for Windows, the only platform it ships for) never reaches the
// endpoint agent's action packages.
func TestCollectorDoesNotCompileInAgentActions(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go tool not available")
	}
	for _, arch := range []string{"amd64", "arm64"} {
		cmd := exec.Command(gobin, "list", "-deps", ".")
		cmd.Env = append(cmd.Environ(), "GOOS=windows", "GOARCH="+arch)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go list: %v", err)
		}
		deps := string(out)
		for _, banned := range []string{"/internal/scripts", "/internal/remote", "/internal/wipe", "/internal/signin",
			"/internal/lostmode", "/internal/commands", "/internal/agent", "/internal/collect"} {
			for _, line := range strings.Split(deps, "\n") {
				if strings.HasSuffix(line, banned) || strings.Contains(line, banned+"/") {
					t.Errorf("windows/%s collector imports %s", arch, line)
				}
			}
		}
		if !strings.Contains(deps, "/internal/directory") || !strings.Contains(deps, "/internal/collector") {
			t.Error("collector does not import its own packages?")
		}
	}
}
