//go:build darwin

package preflight

import (
    "bytes"
    "errors"
    "os/exec"
    "strings"
)

// execCommand is a hook for tests to replace exec.Command.
var execCommand = exec.Command

// checkAdminGroup runs dscl to read the admin group members.
func checkAdminGroup() ([]string, error) {
    cmd := execCommand("dscl", ".", "-read", "/Groups/admin", "GroupMembership")
    var out bytes.Buffer
    cmd.Stdout = &out
    if err := cmd.Run(); err != nil {
        return nil, err
    }
    // Output format: "GroupMembership: user1 user2"
    parts := strings.SplitN(out.String(), ":", 2)
    if len(parts) != 2 {
        return nil, errors.New("unexpected dscl output")
    }
    users := strings.Fields(strings.TrimSpace(parts[1]))
    return users, nil
}

// CheckLocalAdmin implements macOS admin detection via OpenDirectory (dscl).
func CheckLocalAdmin() error {
    admins, err := checkAdminGroup()
    if err != nil {
        return err
    }
    if len(admins) == 0 {
        return ErrNoLocalAdminPresent
    }
    // Optionally, could verify accounts are enabled, but macOS admin accounts are enabled by default.
    return nil
}
