package main

import (
	"os/exec"
	"strings"
	"testing"
)

// Network discovery scans run ONLY in the dedicated collector: the endpoint
// agent binary must not contain the scan engine or the SNMP library.
func TestAgentDoesNotCompileInNetworkScanning(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go tool not available")
	}
	for _, target := range [][2]string{{"windows", "amd64"}, {"windows", "arm64"}, {"darwin", "arm64"}, {"darwin", "amd64"}} {
		cmd := exec.Command(gobin, "list", "-deps", ".")
		cmd.Env = append(cmd.Environ(), "GOOS="+target[0], "GOARCH="+target[1])
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go list %v: %v", target, err)
		}
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasSuffix(line, "/internal/netscan") || strings.Contains(line, "gosnmp") ||
				strings.HasSuffix(line, "/internal/collector") {
				t.Errorf("%s/%s agent imports %s", target[0], target[1], line)
			}
		}
	}
}
