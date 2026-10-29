package signin

import (
	"encoding/json"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/lostmode"
)

// StateFileName is the suspend-sign-in record in the protected state
// directory, next to state.json/lostmode.json/policy.json.
const StateFileName = "signin.json"

// Phase tracks where a suspend-or-restore operation is, so a crash mid-way
// can be detected and finished-or-rolled-back on the next agent start
// (internal/update's Pending/Phase/OnStart machinery is the model; the
// startup recovery itself is wired up in a later change).
type Phase string

const (
	PhaseSnapshotting Phase = "snapshotting" // suspend: Previous captured and persisted; live state not yet touched
	PhaseApplying     Phase = "applying"     // suspend: live change in progress
	PhaseApplied      Phase = "applied"      // suspend: fully applied and verified
	PhaseRestoring    Phase = "restoring"    // restore: live restore in progress
)

// Pending marks an in-progress operation, for crash recovery.
type Pending struct {
	Phase     Phase     `json:"phase"`
	StartedAt time.Time `json:"started_at"`
	Attempts  int       `json:"attempts"`
	LastError string    `json:"last_error,omitempty"`
}

// Snapshot captures everything Suspend is about to change, so Restore can put
// it back exactly. Previous.LogonRestriction is platform-specific and opaque
// here (see signin_windows.go's winLogonSnapshot and signin_darwin.go's
// macLogonSnapshot).
type Snapshot struct {
	LogonRestriction json.RawMessage `json:"logon_restriction"`
	Banner           lostmode.Notice `json:"banner"`
}

// Record is persisted for the whole lifetime of a suspension: from the moment
// the snapshot is durably saved (BEFORE any live change) until Restore
// deletes it. Active is true from that first save, mirroring lostmode's
// "persist first" rule.
type Record struct {
	Active     bool      `json:"active"`
	IncidentID string    `json:"incident_id"`
	CommandID  string    `json:"command_id"`
	Since      time.Time `json:"since"`
	// AdminsAtTime are the enabled local admin names pre-flight found, for audit.
	AdminsAtTime []string `json:"admins_at_time"`
	// KeptServiceAccounts are built-in service/virtual-account SIDs the
	// Windows backend deliberately left holding the logon rights (never
	// removed): see signin_windows.go's isServiceVirtualPrincipal. Empty on
	// macOS.
	KeptServiceAccounts []string    `json:"kept_service_accounts,omitempty"`
	LAPS                *LAPSStatus `json:"laps,omitempty"`
	Previous            Snapshot    `json:"previous"`
	Pending             *Pending    `json:"pending,omitempty"`
}
