// Package model defines the JSON documents exchanged with the CNAPP server.
// They mirror backend/app/schemas_devices.py; the server rejects unknown fields.
package model

import "time"

// Posture check statuses.
const (
	StatusPass    = "pass"
	StatusFail    = "fail"
	StatusUnknown = "unknown"
	StatusInfo    = "info"
)

// Disk is one fixed volume.
type Disk struct {
	Mount      string `json:"mount"`
	Filesystem string `json:"filesystem"`
	SizeBytes  *int64 `json:"size_bytes"`
	FreeBytes  *int64 `json:"free_bytes"`
}

// NetInterface is one network adapter with a MAC address.
type NetInterface struct {
	Name string   `json:"name"`
	MAC  string   `json:"mac"`
	IPs  []string `json:"ips"`
}

// DeviceInfo is hardware / OS inventory.
type DeviceInfo struct {
	Hostname      string         `json:"hostname"`
	OSFamily      string         `json:"os_family"`
	OSName        string         `json:"os_name"`
	OSVersion     string         `json:"os_version"`
	OSBuild       string         `json:"os_build"`
	Architecture  string         `json:"architecture"`
	SerialNumber  string         `json:"serial_number"`
	Manufacturer  string         `json:"manufacturer"`
	Model         string         `json:"model"`
	CPU           string         `json:"cpu"`
	CPUCores      *int           `json:"cpu_cores"`
	MemoryBytes   *int64         `json:"memory_bytes"`
	Disks         []Disk         `json:"disks"`
	UptimeSeconds *int64         `json:"uptime_seconds"`
	LastBoot      *time.Time     `json:"last_boot"`
	LoggedInUsers []string       `json:"logged_in_users"`
	Network       []NetInterface `json:"network"`
	Timezone      string         `json:"timezone"`
	AgentVersion  string         `json:"agent_version"`
}

// PostureCheck is the result of one security posture check.
type PostureCheck struct {
	Status string         `json:"status"`
	Detail string         `json:"detail"`
	Error  *string        `json:"error,omitempty"`
	Data   map[string]any `json:"data"`
}

// Software is one installed application.
type Software struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Publisher   string `json:"publisher"`
	Identifier  string `json:"identifier"`
	InstallDate string `json:"install_date"`
	Source      string `json:"source"`
}

// Report is the check-in document (POST /api/agent/checkin).
type Report struct {
	SchemaVersion int                     `json:"schema_version"`
	CollectedAt   time.Time               `json:"collected_at"`
	Device        DeviceInfo              `json:"device"`
	Posture       map[string]PostureCheck `json:"posture"`
	Software      []Software              `json:"software"`
	Errors        map[string]string       `json:"errors"`
	// MachineID is the SHA-256 of the OS machine identifier; sent at enrollment only.
	MachineID string `json:"-"`
}

// Command is a remote action delivered by the server.
type Command struct {
	ID        string         `json:"id"`
	DeviceID  string         `json:"device_id"`
	Type      string         `json:"type"`
	Params    map[string]any `json:"params"`
	Nonce     string         `json:"nonce"`
	IssuedAt  time.Time      `json:"issued_at"`
	ExpiresAt time.Time      `json:"expires_at"`
}

// CommandList is GET /api/agent/commands.
type CommandList struct {
	ServerTime time.Time `json:"server_time"`
	Commands   []Command `json:"commands"`
}

// Check builds a PostureCheck.
func Check(status, detail string, data map[string]any) PostureCheck {
	if data == nil {
		data = map[string]any{}
	}
	return PostureCheck{Status: status, Detail: detail, Data: data}
}

// Unknown builds an "unknown" check carrying the error that prevented it.
func Unknown(detail string, err error) PostureCheck {
	c := Check(StatusUnknown, detail, nil)
	if err != nil {
		msg := err.Error()
		if len(msg) > 1000 {
			msg = msg[:1000]
		}
		c.Error = &msg
	}
	return c
}
