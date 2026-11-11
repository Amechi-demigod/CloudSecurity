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
	// DirectoryJoin: domain / cloud-directory membership facts (nil when the
	// machine is not joined to anything this agent can detect).
	DirectoryJoin *DirectoryJoin `json:"directory_join,omitempty"`
	// Classification: role, form factor and virtualisation (agents 1.4.0+;
	// nil when nothing could be determined).
	Classification *Classification `json:"classification,omitempty"`
}

// Device roles and form factors (Classification).
const (
	RoleWorkstation      = "workstation"
	RoleServer           = "server"
	RoleDomainController = "domain_controller"

	FormLaptop  = "laptop"
	FormDesktop = "desktop"
	FormServer  = "server"
	FormTablet  = "tablet"
	FormOther   = "other"
)

// Classification tells workstations from servers, domain controllers and
// virtual machines. Everything is read locally (OS product type, SMBIOS /
// DMI, CPUID); no network calls, no cloud metadata service. Fields are ""
// / nil when unknown.
type Classification struct {
	Role            string `json:"role"`
	RoleSource      string `json:"role_source"`
	FormFactor      string `json:"form_factor"`
	ChassisType     *int   `json:"chassis_type"`
	IsVirtual       *bool  `json:"is_virtual"`
	Hypervisor      string `json:"hypervisor"`
	CloudProvider   string `json:"cloud_provider"`
	CloudInstanceID string `json:"cloud_instance_id"`
}

// DirectoryJoin describes the directories this computer is joined to, used by
// the server to match the device to directory (AD / Entra) computer objects.
// Every field is optional ("" when unknown); GUIDs are lower-case 8-4-4-4-12.
type DirectoryJoin struct {
	ADDomain           string `json:"ad_domain"`
	ADNetbios          string `json:"ad_netbios"`
	ADForest           string `json:"ad_forest"`
	ADDomainSID        string `json:"ad_domain_sid"`
	ADComputerSID      string `json:"ad_computer_sid"`
	ADObjectGUID       string `json:"ad_object_guid"`
	DNSHostname        string `json:"dns_hostname"`
	EntraDeviceID      string `json:"entra_device_id"`
	EntraTenantID      string `json:"entra_tenant_id"`
	EntraJoinType      string `json:"entra_join_type"`
	IntuneEnrollmentID string `json:"intune_enrollment_id"`
	Source             string `json:"source"`
}

// Empty reports whether nothing is known.
func (j *DirectoryJoin) Empty() bool {
	return j == nil || (j.ADDomain == "" && j.ADNetbios == "" && j.ADComputerSID == "" && j.EntraDeviceID == "" &&
		j.EntraTenantID == "" && j.IntuneEnrollmentID == "" && j.ADObjectGUID == "")
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
	// Linux packages (agents 1.7.0+; omitted elsewhere): the OSV ecosystem of
	// the OS ("" = OSV has no feed, e.g. Amazon Linux: reported, not matched),
	// the source package and (dpkg) source version vulnerability feeds key on.
	Ecosystem     string `json:"ecosystem,omitempty"`
	SourceName    string `json:"source_name,omitempty"`
	SourceVersion string `json:"source_version,omitempty"`
}

// Service is one Windows service or Linux systemd service (internal/actions on
// Windows, internal/collect on Linux 1.7.0+): the
// inventory the console's Services tab and endpoint actions work from.
type Service struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	// Status: running | stopped | start_pending | stop_pending | paused | other.
	Status string `json:"status"`
	// StartType: boot | system | auto | auto_delayed | manual | disabled.
	StartType string `json:"start_type"`
}

// Report is the check-in document (POST /api/agent/checkin).
type Report struct {
	SchemaVersion int                     `json:"schema_version"`
	CollectedAt   time.Time               `json:"collected_at"`
	Device        DeviceInfo              `json:"device"`
	Posture       map[string]PostureCheck `json:"posture"`
	Software      []Software              `json:"software"`
	// Services: Windows services and Linux systemd services (nil on macOS, then omitted).
	Services []Service         `json:"services,omitempty"`
	Errors   map[string]string `json:"errors"`
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
