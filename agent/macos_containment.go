//go:build darwin

package preflight

import (
    "bytes"
    "errors"
    "strings"
)

// execCommand is hookable for tests (same name as in preflight_darwin.go). It is defined there; reuse.

// macOS containment utilities using dscl.

type macOSSnapshot struct {
    AuthAuthority string // may be empty if attribute not set
}

// takeMacSnapshot reads the AuthenticationAuthority attribute for the user.
func takeMacSnapshot(username string) (macOSSnapshot, error) {
    cmd := execCommand("dscl", ".", "-read", "/Users/"+username, "AuthenticationAuthority")
    var out bytes.Buffer
    cmd.Stdout = &out
    if err := cmd.Run(); err != nil {
        // If attribute missing, dscl returns error; treat as empty snapshot.
        if strings.Contains(err.Error(), "No such key") {
            return macOSSnapshot{AuthAuthority: ""}, nil
        }
        return macOSSnapshot{}, err
    }
    parts := strings.SplitN(out.String(), ":", 2)
    if len(parts) != 2 {
        return macOSSnapshot{}, errors.New("unexpected dscl output for AuthenticationAuthority")
    }
    return macOSSnapshot{AuthAuthority: strings.TrimSpace(parts[1])}, nil
}

// containUserMac disables the user by setting AuthenticationAuthority to ;DisabledUser;.
func containUserMac(username string) error {
    // Use dscl to set the attribute.
    cmd := execCommand("dscl", ".", "-create", "/Users/"+username, "AuthenticationAuthority", ";DisabledUser;")
    return cmd.Run()
}

// restoreUserMac restores the original AuthenticationAuthority attribute.
func restoreUserMac(username string, snap macOSSnapshot) error {
    if snap.AuthAuthority == "" {
        // Delete attribute.
        cmd := execCommand("dscl", ".", "-delete", "/Users/"+username, "AuthenticationAuthority")
        return cmd.Run()
    }
    // Restore previous value.
    cmd := execCommand("dscl", ".", "-create", "/Users/"+username, "AuthenticationAuthority", snap.AuthAuthority)
    return cmd.Run()
}
