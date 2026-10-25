package preflight

import (
    "errors"
)

// AccountRightsSnapshot captures the set of privileges a user had before containment.
// The key is the privilege name (e.g. "SeInteractiveLogonRight").
// The value is true (present).
type AccountRightsSnapshot map[string]bool

// LsaAPI abstracts the Windows LSA functions we need. In production it calls the real system
// calls; on non‑Windows platforms a dummy in‑memory implementation is used.
type LsaAPI interface {
    // EnumerateAccountRights returns the list of current privileges for the given user.
    EnumerateAccountRights(username string) ([]string, error)
    // AddAccountRights adds the supplied privileges to the user.
    AddAccountRights(username string, rights []string) error
    // RemoveAccountRights removes the supplied privileges from the user.
    RemoveAccountRights(username string, rights []string) error
}

// lsaImpl is the concrete implementation used at runtime. It is set in init() of the
// platform‑specific files (lsa_windows.go or lsa_dummy.go).
var lsaImpl LsaAPI

// ErrContainmentFailed is returned when the containment workflow cannot be completed.
var ErrContainmentFailed = errors.New("containment operation failed")

// TakeSnapshot records the current rights for the given local account.
func TakeSnapshot(username string) (AccountRightsSnapshot, error) {
    rights, err := lsaImpl.EnumerateAccountRights(username)
    if err != nil {
        return nil, err
    }
    snap := make(AccountRightsSnapshot, len(rights))
    for _, r := range rights {
        snap[r] = true
    }
    return snap, nil
}

// ContainUser adds a deny‑logon right to the account, effectively isolating it.
// The deny right used here is "SeDenyInteractiveLogonRight" – adjust as needed.
func ContainUser(username string) error {
    // Add the deny right.
    if err := lsaImpl.AddAccountRights(username, []string{"SeDenyInteractiveLogonRight"}); err != nil {
        return err
    }
    return nil
}

// RestoreUser restores the original rights from a snapshot and removes any deny rights that were added.
func RestoreUser(username string, snap AccountRightsSnapshot) error {
    // First, remove the deny right we added during containment.
    if err := lsaImpl.RemoveAccountRights(username, []string{"SeDenyInteractiveLogonRight"}); err != nil {
        return err
    }
    // Re‑apply the original rights captured in the snapshot.
    var original []string
    for r := range snap {
        original = append(original, r)
    }
    // Remove all rights first to avoid duplicates, then add the original set.
    // In a real implementation we would enumerate current rights and diff them.
    if err := lsaImpl.RemoveAccountRights(username, original); err != nil {
        // If removal fails we still try to add back the original rights.
        // Continue with best effort.
    }
    if err := lsaImpl.AddAccountRights(username, original); err != nil {
        return err
    }
    return nil
}

// init sets a safe default implementation for non‑Windows builds.
func init() {
    // The platform‑specific files replace lsaImpl with a proper implementation.
    // If none is provided we fall back to a dummy that always succeeds.
    if lsaImpl == nil {
        lsaImpl = newDummyLsa()
    }
}
