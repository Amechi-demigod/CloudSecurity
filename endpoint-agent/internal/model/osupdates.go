package model

import "time"

// OSUpdateReport is the result of a Windows Update search (POST
// /api/agent/os-updates); it mirrors backend/app/schemas_os_updates.py.
// Read-only: it lists what is missing, nothing is installed.
type OSUpdateReport struct {
	SchemaVersion        int             `json:"schema_version"`
	ScannedAt            time.Time       `json:"scanned_at"`
	Status               string          `json:"status"` // ok | failed
	Error                string          `json:"error"`
	Trigger              string          `json:"trigger"` // schedule | command
	DurationSeconds      *int            `json:"duration_seconds"`
	Source               string          `json:"source"` // wsus | wufb | microsoft_update | windows_update | unknown
	SourceDetail         string          `json:"source_detail"`
	ServiceState         string          `json:"service_state"`
	ServiceStartType     string          `json:"service_start_type"`
	RebootPending        bool            `json:"reboot_pending"`
	LastSearchSuccessAt  *time.Time      `json:"last_search_success_at"`
	LastInstallSuccessAt *time.Time      `json:"last_install_success_at"`
	Updates              []MissingUpdate `json:"updates"`
}

// MissingUpdate is one applicable, not installed, not hidden software update.
type MissingUpdate struct {
	UpdateID       string   `json:"update_id"`
	KBIDs          []string `json:"kb_ids"`
	Title          string   `json:"title"`
	Classification string   `json:"classification"`
	MsrcSeverity   string   `json:"msrc_severity"`
	ReleaseDate    *string  `json:"release_date"` // YYYY-MM-DD
	CVEIDs         []string `json:"cve_ids"`
	RebootBehavior string   `json:"reboot_behavior"` // never | always | can_request
	SizeBytes      *int64   `json:"size_bytes"`
	Downloaded     bool     `json:"downloaded"`
}
