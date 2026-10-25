package preflight

import (
    "errors"
    "os"
    "runtime"
)

// ErrNoLocalAdminPresent is returned when no enabled local administrator is detected.
var ErrNoLocalAdminPresent = errors.New("no local administrator present")

// LAPSStatus represents the Windows LAPS configuration status.
type LAPSStatus string

const (
    // LAPSReadOnly indicates LAPS is enabled but passwords are read‑only.
    LAPSReadOnly LAPSStatus = "read-only"
    // LAPSNeverPasswords indicates LAPS is configured to never store passwords.
    LAPSNeverPasswords LAPSStatus = "never passwords"
    // LAPSDisabled indicates LAPS is not enabled on the system.
    LAPSDisabled LAPSStatus = "disabled"
)


// GetLAPSStatus reports the Windows LAPS configuration.
// It returns LAPSDisabled on non‑Windows platforms.
// The implementation reads the environment variable LAPS_STATUS for demo purposes.
func GetLAPSStatus() (LAPSStatus, error) {
    if runtime.GOOS != "windows" {
        return LAPSDisabled, nil
    }
    // In a real implementation this would query the registry or LAPS API.
    // Here we use an env var to simulate the status.
    s := os.Getenv("LAPS_STATUS")
    switch s {
    case "read-only":
        return LAPSReadOnly, nil
    case "never":
        return LAPSNeverPasswords, nil
    default:
        return LAPSDisabled, nil
    }
}
