package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// PolicyFileName holds device-local settings that only a local administrator
// (installer, MDM/GPO script) can change. The CNAPP server has no command that
// writes it: a compromised server cannot opt a device in to remote wipe.
const PolicyFileName = "policy.json"

// Policy is the content of policy.json.
type Policy struct {
	// AllowWipe: the device opted in to remote wipe at install time (MSI
	// property CNAPP_ALLOW_WIPE=1, the console's "Allow remote wipe" installer
	// option, or `cnapp-agent configure --allow-wipe=1`). Default false.
	AllowWipe bool      `json:"allow_wipe"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
	Source    string    `json:"source,omitempty"`
}

// PolicyFile is the full path of policy.json.
func (p Paths) PolicyFile() string { return filepath.Join(p.StateDir, PolicyFileName) }

// LoadPolicy reads policy.json (a missing file is the default policy). Outside
// of --home (test) mode the file must be owned by SYSTEM/Administrators or root.
func LoadPolicy(p Paths) (Policy, error) {
	f := p.PolicyFile()
	info, err := os.Lstat(f)
	if errors.Is(err, os.ErrNotExist) {
		return Policy{}, nil
	}
	if err != nil {
		return Policy{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return Policy{}, fmt.Errorf("%s is not a small regular file", f)
	}
	if !p.Custom {
		if err := checkPrivilegedOwner(f); err != nil {
			return Policy{}, fmt.Errorf("refusing %s: %w", f, err)
		}
	}
	b, err := os.ReadFile(f)
	if err != nil {
		return Policy{}, err
	}
	var pol Policy
	if err := json.Unmarshal(b, &pol); err != nil {
		return Policy{}, fmt.Errorf("corrupt %s: %w", f, err)
	}
	return pol, nil
}

// SavePolicy writes policy.json with the same protection as state.json.
func SavePolicy(p Paths, pol Policy) error {
	b, err := json.MarshalIndent(pol, "", "  ")
	if err != nil {
		return err
	}
	return writeSecure(p.StateDir, p.PolicyFile(), b)
}

// ParseBoolSetting parses an installer property: "" = not set (nil), else
// 1/true/yes/on or 0/false/no/off.
func ParseBoolSetting(s string) (*bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return nil, nil
	case "1", "true", "yes", "on":
		v := true
		return &v, nil
	case "0", "false", "no", "off":
		v := false
		return &v, nil
	}
	return nil, fmt.Errorf("invalid value %q (want 1 or 0)", s)
}
