// +build !windows,!darwin

package preflight

// CheckLocalAdmin is a no‑op for platforms other than Windows and macOS.
func CheckLocalAdmin() error {
    // Assume an admin exists.
    return nil
}
