// Package state persists the agent's enrollment (server URL, device id and
// secret) and small bits of runtime state in a file only SYSTEM/Administrators
// (Windows) or root (macOS) can read.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// FileName of the state document inside the state directory.
const FileName = "state.json"

// MaxExecuted is how many executed command ids are remembered (replay guard).
const MaxExecuted = 500

// ErrNotEnrolled is returned by Load when no state file exists.
var ErrNotEnrolled = errors.New("agent is not enrolled (run `cnapp-agent enroll`)")

// State is the persisted agent state.
type State struct {
	ServerURL              string    `json:"server_url"`
	DeviceID               string    `json:"device_id"`
	DeviceSecret           string    `json:"device_secret"`
	InsecureDev            bool      `json:"insecure_dev,omitempty"`
	CAFile                 string    `json:"ca_file,omitempty"`
	EnrolledAt             time.Time `json:"enrolled_at"`
	CheckInIntervalSeconds int       `json:"check_in_interval_seconds"`
	CommandPollSeconds     int       `json:"command_poll_seconds"`
	LastCheckIn            time.Time `json:"last_check_in,omitempty"`
	ExecutedCommands       []string  `json:"executed_commands,omitempty"`
	// ScriptBundleVersion is the highest signed script-bundle version this agent
	// has run a script from; older bundles are refused (anti-rollback).
	ScriptBundleVersion string `json:"script_bundle_version,omitempty"`
}

// Paths are the agent's directories.
type Paths struct {
	StateDir string
	LogDir   string
	// Custom is true for a --home / CNAPP_AGENT_HOME location (tests,
	// development): ownership checks meant for the system location are skipped.
	Custom bool
}

// StateFile is the full path of state.json.
func (p Paths) StateFile() string { return filepath.Join(p.StateDir, FileName) }

// LogFile is the agent log path.
func (p Paths) LogFile() string { return filepath.Join(p.LogDir, "agent.log") }

// Resolve returns the platform default paths, or <home>/state and <home>/logs
// when home (flag --home or env CNAPP_AGENT_HOME) is set (tests, development).
func Resolve(home string) Paths {
	if home == "" {
		home = os.Getenv("CNAPP_AGENT_HOME")
	}
	if home != "" {
		return Paths{StateDir: filepath.Join(home, "state"), LogDir: filepath.Join(home, "logs"), Custom: true}
	}
	return defaultPaths()
}

// ValidateServerURL enforces https (http only with insecureDev) and strips the path.
func ValidateServerURL(raw string, insecureDev bool) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid server URL %q", raw)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !insecureDev {
			return "", errors.New("refusing plain http: the server URL must be https:// (use --insecure-dev only for local testing)")
		}
	default:
		return "", fmt.Errorf("unsupported URL scheme %q", u.Scheme)
	}
	if u.User != nil {
		return "", errors.New("server URL must not contain credentials")
	}
	return u.Scheme + "://" + u.Host + strings.TrimRight(u.Path, "/"), nil
}

// Load reads the state file.
func Load(p Paths) (*State, error) {
	b, err := os.ReadFile(p.StateFile())
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotEnrolled
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("corrupt state file %s: %w", p.StateFile(), err)
	}
	if s.DeviceID == "" || s.DeviceSecret == "" || s.ServerURL == "" {
		return nil, ErrNotEnrolled
	}
	return &s, nil
}

// Save writes the state atomically (temp file + rename) with restrictive permissions.
func Save(p Paths, s *State) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeSecure(p.StateDir, p.StateFile(), b)
}

// CAFileName is the copy of the private CA bundle kept next to state.json.
const CAFileName = "ca.pem"

// CAFile is where SaveCA stores the trusted private CA bundle.
func (p Paths) CAFile() string { return filepath.Join(p.StateDir, CAFileName) }

// SaveCA copies a PEM CA bundle into the protected state directory, so the
// agent keeps trusting a private CA after the file given to `enroll --ca-file`
// (e.g. a download) is deleted, and only SYSTEM/Administrators (Windows) or
// root (macOS) can change which CA the agent trusts.
func SaveCA(p Paths, pem []byte) (string, error) {
	if err := writeSecure(p.StateDir, p.CAFile(), pem); err != nil {
		return "", err
	}
	return p.CAFile(), nil
}

// WriteFile writes name inside the protected state directory atomically, with
// the same restrictive permissions as state.json (used for update.json).
func WriteFile(p Paths, name string, data []byte) error {
	return writeSecure(p.StateDir, filepath.Join(p.StateDir, name), data)
}

// writeSecure writes data to dst (inside dir) atomically with restrictive permissions.
func writeSecure(dir, dst string, data []byte) error {
	if err := SecureDir(dir); err != nil {
		return fmt.Errorf("securing %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := restrictFile(tmp); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return replaceFile(tmp.Name(), dst)
}

// Remove deletes the state file, the stored CA bundle, the local policy, the
// lost-mode record and any pending enrollment config (uninstall --purge).
func Remove(p Paths) error {
	if err := RemoveEnrollConfig(p); err != nil {
		return err
	}
	for _, f := range []string{p.StateFile(), p.CAFile(), p.PolicyFile(), filepath.Join(p.StateDir, "lostmode.json")} {
		if err := os.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// MarkExecuted records a command id; false if it was already executed.
func (s *State) MarkExecuted(id string) bool {
	if slices.Contains(s.ExecutedCommands, id) {
		return false
	}
	s.ExecutedCommands = append(s.ExecutedCommands, id)
	if len(s.ExecutedCommands) > MaxExecuted {
		s.ExecutedCommands = s.ExecutedCommands[len(s.ExecutedCommands)-MaxExecuted:]
	}
	return true
}

// Redacted is the state without the secret (for `status` and log bundles).
func (s State) Redacted() State {
	if s.DeviceSecret != "" {
		s.DeviceSecret = "<redacted>"
	}
	return s
}
