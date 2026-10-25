package preflight

import (
    "testing"
)

func TestContainAndRestore(t *testing.T) {
    user := "testuser"
    // Ensure dummy LSA starts clean.
    // Take initial snapshot (should be empty).
    snap, err := TakeSnapshot(user)
    if err != nil {
        t.Fatalf("TakeSnapshot error: %v", err)
    }
    if len(snap) != 0 {
        t.Fatalf("expected empty snapshot, got %d rights", len(snap))
    }

    // Contain the user – adds deny right.
    if err := ContainUser(user); err != nil {
        t.Fatalf("ContainUser error: %v", err)
    }
    rights, _ := lsaImpl.EnumerateAccountRights(user)
    found := false
    for _, r := range rights {
        if r == "SeDenyInteractiveLogonRight" {
            found = true
            break
        }
    }
    if !found {
        t.Fatalf("deny right not added during containment")
    }

    // Restore using snapshot – should remove deny right.
    if err := RestoreUser(user, snap); err != nil {
        t.Fatalf("RestoreUser error: %v", err)
    }
    rights, _ = lsaImpl.EnumerateAccountRights(user)
    for _, r := range rights {
        if r == "SeDenyInteractiveLogonRight" {
            t.Fatalf("deny right still present after restore")
        }
    }
}
