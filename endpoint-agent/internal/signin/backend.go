package signin

import (
	"context"
	"encoding/json"
)

// AdminProbe answers "is there at least one enabled local administrator
// account", by name, for pre-flight lockout prevention. A member that cannot
// be confirmed as a local, enabled account (for example an Entra ID / Azure
// AD principal in the Administrators group) must never be counted.
type AdminProbe interface {
	EnabledLocalAdmins(ctx context.Context) ([]string, error)
}

// LAPSStatus reports Windows LAPS configuration (policy/config only). It must
// never carry a password: see laps_windows.go's doc comment.
type LAPSStatus struct {
	Configured      bool   `json:"configured"`
	Source          string `json:"source,omitempty"` // "legacy_laps" | "windows_laps_gpo" | "windows_laps_mdm" | ""
	BackupToEntraID *bool  `json:"backup_to_entra_id,omitempty"`
	Detail          string `json:"detail,omitempty"`
}

// LAPSProbe reports LAPS configuration. Windows only; nil elsewhere.
type LAPSProbe interface {
	Status(ctx context.Context) (LAPSStatus, error)
}

// SessionTerminator signs out interactive sessions that do not belong to one
// of the given (already pre-flight-confirmed) local admin accounts.
type SessionTerminator interface {
	SignOutNonAdmins(ctx context.Context, adminNames []string) (string, error)
}

// Backend applies, restores and verifies the platform-specific mechanism that
// blocks standard interactive sign-in, plus the sign-in banner (reused from
// lostmode's registry/defaults Get/Set/Restore).
type Backend interface {
	// CaptureLogonRestriction reads the CURRENT state of whatever mechanism
	// this platform uses to allow/deny interactive sign-in, unmodified.
	CaptureLogonRestriction(ctx context.Context) (json.RawMessage, error)
	// ApplyLogonRestriction is the FIRST-TIME apply: it blocks standard/domain
	// users, keeping previous (the just-captured snapshot) available so a
	// failed/unsafe apply can be reverted immediately. Returns a
	// human-readable detail string and the built-in service/virtual-account
	// SIDs deliberately left untouched (Windows only; nil elsewhere) - the
	// caller persists these as Record.KeptServiceAccounts for the console.
	ApplyLogonRestriction(ctx context.Context, adminNames []string, previous json.RawMessage) (detail string, kept []string, err error)
	// ReapplyLogonRestriction is used for a REPEAT Suspend or periodic
	// Reenforce: it only reconciles toward the already-suspended target and
	// NEVER restores the pre-suspend state on failure - the device must stay
	// suspended. previous is still needed (e.g. to recompute which built-in
	// service/virtual accounts to keep on Windows).
	ReapplyLogonRestriction(ctx context.Context, adminNames []string, previous json.RawMessage) (detail string, kept []string, err error)
	// RestoreLogonRestriction writes back exactly what CaptureLogonRestriction read.
	RestoreLogonRestriction(ctx context.Context, previous json.RawMessage) error
	// VerifyStandardSignInBlocked re-reads effective state and confirms only
	// admins (and, on Windows, built-in service/virtual accounts) can sign in.
	VerifyStandardSignInBlocked(ctx context.Context, adminNames []string) (bool, string, error)
	// VerifyStandardSignInWorks re-reads effective state and confirms it
	// matches the given pre-suspend snapshot.
	VerifyStandardSignInWorks(ctx context.Context, previous json.RawMessage) (bool, string, error)
	// Name describes the mechanism for result output.
	Name() string
}

// LostModeChecker reports whether lost mode is currently active, so Suspend
// can refuse to run alongside it: both compete for the sign-in screen and
// session control, and layering one on top of the other risks an
// unreviewable mixed state.
type LostModeChecker interface {
	Active(ctx context.Context) (bool, error)
}

// RolledBackError wraps an apply/restrict failure where the backend itself
// successfully undid everything it had changed before the failure - the live
// state is confirmed to match the pre-suspend snapshot, so the caller may
// delete the suspend-sign-in record. Any OTHER error from
// Backend.ApplyLogonRestriction must be treated conservatively: the live
// state is NOT assumed clean, and the record must be kept so a human (or a
// future crash-recovery pass) can resolve it.
type RolledBackError struct{ Err error }

func (e *RolledBackError) Error() string { return e.Err.Error() }
func (e *RolledBackError) Unwrap() error { return e.Err }
