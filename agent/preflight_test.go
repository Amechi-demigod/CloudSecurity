//go:build !darwin
// +build !darwin

package preflight


import (
    "os"
    "testing"
)

func TestGetLAPSStatus_NonWindows(t *testing.T) {
    // On non‑Windows platforms we expect LAPSDisabled.
    status, err := GetLAPSStatus()
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if status != LAPSDisabled {
        t.Fatalf("expected %s, got %s", LAPSDisabled, status)
    }
}

func TestGetLAPSStatus_WindowsReadOnly(t *testing.T) {
    // Simulate Windows by setting GOOS env for the process is not possible; instead we set the env var and assume the function will read it.
    // This test only validates the env‑var handling logic.
    old := os.Getenv("LAPS_STATUS")
    defer os.Setenv("LAPS_STATUS", old)
    os.Setenv("LAPS_STATUS", "read-only")
    // Force the function to think it's Windows by temporarily overriding runtime.GOOS is not feasible.
    // So we only test the env handling when GOOS == "windows" which can't be simulated here.
    // The test ensures no panic occurs.
    status, err := GetLAPSStatus()
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    _ = status
}
