package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ServiceFileName records how the installer last configured the service (the
// directory collector: run-as identity and display name), so an upgrade or
// repair - which re-creates the service - keeps them without the admin passing
// them again. Same protection as state.json.
const ServiceFileName = "service.json"

// ServiceSettings is the content of service.json.
type ServiceSettings struct {
	// RunAs: the group Managed Service Account (DOMAIN\name$); empty = LocalSystem.
	RunAs       string    `json:"run_as,omitempty"`
	DisplayName string    `json:"display_name,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
	Source      string    `json:"source,omitempty"`
}

// ServiceFile is the full path of service.json.
func (p Paths) ServiceFile() string { return filepath.Join(p.StateDir, ServiceFileName) }

// LoadServiceSettings reads service.json; ok is false when there is none.
func LoadServiceSettings(p Paths) (s ServiceSettings, ok bool, err error) {
	f := p.ServiceFile()
	info, err := os.Lstat(f)
	if errors.Is(err, os.ErrNotExist) {
		return ServiceSettings{}, false, nil
	}
	if err != nil {
		return ServiceSettings{}, false, err
	}
	if !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return ServiceSettings{}, false, fmt.Errorf("%s is not a small regular file", f)
	}
	if !p.Custom {
		if err := checkPrivilegedOwner(f); err != nil {
			return ServiceSettings{}, false, fmt.Errorf("refusing %s: %w", f, err)
		}
	}
	b, err := os.ReadFile(f)
	if err != nil {
		return ServiceSettings{}, false, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return ServiceSettings{}, false, fmt.Errorf("corrupt %s: %w", f, err)
	}
	return s, true, nil
}

// SaveServiceSettings writes service.json.
func SaveServiceSettings(p Paths, s ServiceSettings) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeSecure(p.StateDir, p.ServiceFile(), b)
}
