//go:build darwin

package preflight

import (
    "os/exec"
    "testing"
)

// stub to capture exec calls and provide controlled output
var execCalls []struct {
    name string
    args []string
}

func resetStub() {
    execCalls = nil
    execCommand = func(name string, args ...string) *exec.Cmd {
        execCalls = append(execCalls, struct{ name string; args []string }{name, args})
        // Determine behavior based on command
        if name == "dscl" && contains(args, "-read") && contains(args, "AuthenticationAuthority") {
            // Simulate dscl output for existing attribute
            // Using printf to write to stdout
            return exec.Command("printf", "AuthenticationAuthority: ;ShadowHash; ;SecureToken;\n")
        }
        // For other dscl commands, just succeed
        return exec.Command("true")
    }
}

func contains(slice []string, val string) bool {
    for _, s := range slice {
        if s == val {
            return true
        }
    }
    return false
}

func TestTakeMacSnapshotExists(t *testing.T) {
    resetStub()
    snap, err := takeMacSnapshot("bob")
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if snap.AuthAuthority == "" {
        t.Fatalf("expected non‑empty AuthAuthority")
    }
    // Verify that dscl -read was called
    found := false
    for _, c := range execCalls {
        if c.name == "dscl" && contains(c.args, "-read") {
            found = true
            break
        }
    }
    if !found {
        t.Fatalf("dscl -read not invoked")
    }
}

func TestContainAndRestoreUserMac(t *testing.T) {
    resetStub()
    // First, take a snapshot (will use stub output)
    snap, err := takeMacSnapshot("alice")
    if err != nil {
        t.Fatalf("snapshot error: %v", err)
    }
    // Contain the user
    if err := containUserMac("alice"); err != nil {
        t.Fatalf("contain error: %v", err)
    }
    // Restore the user
    if err := restoreUserMac("alice", snap); err != nil {
        t.Fatalf("restore error: %v", err)
    }
    // Verify call sequence: read, create (disable), create (restore)
    if len(execCalls) < 3 {
        t.Fatalf("expected at least 3 exec calls, got %d", len(execCalls))
    }
    // Check that the second call is a disable (contains ;DisabledUser;)
    second := execCalls[1]
    if !contains(second.args, ";DisabledUser;") {
        t.Fatalf("expected disable call, got args %v", second.args)
    }
    // Check that the third call restores original value (not disabled flag)
    third := execCalls[2]
    if contains(third.args, ";DisabledUser;") {
        t.Fatalf("expected restore call with original value, got disabled flag")
    }
}
