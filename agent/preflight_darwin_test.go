//go:build darwin

package preflight

import (
    "os/exec"
    "testing"
)

func TestCheckLocalAdmin_Darwin_WithAdmins(t *testing.T) {
    // Save original and restore after.
    orig := execCommand
    defer func() { execCommand = orig }()

    // Fake command that writes a non‑empty admin list.
    execCommand = func(name string, args ...string) *exec.Cmd {
        // Use a shell to print the expected dscl output.
        return exec.Command("sh", "-c", "printf 'GroupMembership: alice bob'")
    }

    if err := CheckLocalAdmin(); err != nil {
        t.Fatalf("expected no error, got %v", err)
    }
}

func TestCheckLocalAdmin_Darwin_NoAdmins(t *testing.T) {
    orig := execCommand
    defer func() { execCommand = orig }()

    execCommand = func(name string, args ...string) *exec.Cmd {
        return exec.Command("sh", "-c", "printf 'GroupMembership:'")
    }

    err := CheckLocalAdmin()
    if err == nil {
        t.Fatalf("expected ErrNoLocalAdminPresent, got nil")
    }
    if err != ErrNoLocalAdminPresent {
        t.Fatalf("expected ErrNoLocalAdminPresent, got %v", err)
    }
}
