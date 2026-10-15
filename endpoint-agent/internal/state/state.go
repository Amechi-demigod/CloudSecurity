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
}

// Paths are the agent's directories.
type Paths struct {
	StateDir string
	LogDir   string
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
		return Paths{StateDir: filepath.Join(home, "state"), LogDir: filepath.Join(home, "logs")}
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
	if err := SecureDir(p.StateDir); err != nil {
		return fmt.Errorf("securing %s: %w", p.StateDir, err)
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(p.StateDir, ".state-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := restrictFile(tmp); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
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
	return replaceFile(tmp.Name(), p.StateFile())
}

// Remove deletes the state file (uninstall --purge).
func Remove(p Paths) error {
	err := os.Remove(p.StateFile())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
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
