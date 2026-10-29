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
	// ApplyLogonRestriction blocks standard/domain users, keeping previous
	// (the just-captured snapshot) available so a failed/unsafe apply can be
	// reverted immediately. Returns a human-readable detail string.
	ApplyLogonRestriction(ctx context.Context, adminNames []string, previous json.RawMessage) (detail string, err error)
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
