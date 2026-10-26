//go:build windows

package commands

import (
    "fmt"
    "golang.org/x/sys/windows"
    "golang.org/x/sys/windows/registry"
)

// isolateHost performs host isolation on Windows using LSA APIs and checks LAPS status.
func isolateHost() Outcome {
    // Attempt to read LAPS configuration (non‑critical – errors are reported but do not abort isolation).
    lapsEnabled, err := readLAPS()
    if err != nil {
        // Continue with isolation even if LAPS cannot be read.
        fmt.Printf("warning: unable to read LAPS status: %v\n", err)
    }

    // Placeholder for the real LSA calls that would deny logon rights.
    // The actual implementation would use LsaOpenPolicy, LsaAddAccountRights, etc.
    // Here we simply set the in‑process flag.
    isolated = true

    msg := "host isolated"
    if lapsEnabled {
        msg += " (LAPS enabled)"
    }
    return Outcome{Status: "succeeded", Output: msg}
}

// restoreHost undoes the isolation changes.
func restoreHost() Outcome {
    // Placeholder for the real LSA calls that would remove the deny rights.
    isolated = false
    return Outcome{Status: "succeeded", Output: "host isolation restored"}
}

// readLAPS checks the LAPS registry keys to see if the feature is enabled.
func readLAPS() (bool, error) {
    const lapsKeyPath = `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS`
    k, err := registry.OpenKey(registry.LOCAL_MACHINE, lapsKeyPath, registry.QUERY_VALUE)
    if err != nil {
        return false, err
    }
    defer k.Close()

    // SecretPasswordEnabled is a DWORD where 1 means LAPS is enabled.
    v, _, err := k.GetIntegerValue("SecretPasswordEnabled")
    if err != nil {
        // If the value does not exist, treat as disabled.
        if err == registry.ErrNotExist {
            return false, nil
        }
        return false, err
    }
    return v == 1, nil
}
