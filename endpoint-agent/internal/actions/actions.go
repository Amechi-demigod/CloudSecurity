// Package actions runs the built-in endpoint actions (agents 1.4.0+):
//
//   - manage_service: stop / start a service, set its startup type to
//     Disabled and later restore exactly the startup type it had before
//   - uninstall_software: remove a program with its own silent uninstaller
//     (MSI: msiexec /x {ProductCode} /qn /norestart; otherwise the registry's
//     QuietUninstallString; nothing else)
//   - block_usb_storage / unblock_usb_storage: the standard, reversible
//     USB mass-storage block (USBSTOR driver Start=4 plus the "Removable
//     Disks: Deny read/write/execute" policy), restoring the previous values
//     exactly
//
// Windows only in this version: the command types and parameters are
// OS-neutral, and on other OSes every action answers "unsupported on this OS"
// (platform_other.go). Values the agent replaces are saved in
// endpoint-actions.json in the protected state directory BEFORE anything is
// changed, so "restore" / "unblock" put back exactly what was there, even
// after an agent restart.
//
// All OS access goes through the ServiceControl, Registry and Programs
// interfaces, so the logic here is tested on every OS with fakes.
package actions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/state"
)

// Command types (mirrored in backend/app/services/endpoint_actions.py).
const (
	ManageService     = "manage_service"
	UninstallSoftware = "uninstall_software"
	BlockUSBStorage   = "block_usb_storage"
	UnblockUSBStorage = "unblock_usb_storage"
)

// AllowedParams are the only parameters each command may carry.
var AllowedParams = map[string][]string{
	ManageService:     {"service", "action", "restore_to"},
	UninstallSoftware: {"identifier", "source", "name", "version"},
	BlockUSBStorage:   {},
	UnblockUSBStorage: {},
}

// FileName of the saved previous values inside the state directory. It is
// deliberately not removed by `uninstall --purge`: losing it would make a USB
// block or a disabled service impossible to restore exactly.
const FileName = "endpoint-actions.json"

// ErrUnsupported is returned on operating systems without endpoint actions.
var ErrUnsupported = errors.New("unsupported on this OS: endpoint actions are Windows only in this agent version")

// ErrNotFound: the service or program does not exist on this device.
var ErrNotFound = errors.New("not found")

// Result of an action, reported as the command result.
type Result struct {
	Status   string // succeeded | failed | rejected
	Output   string
	ExitCode *int
	Data     map[string]any
	// Refresh: the software inventory changed; check in once the result is reported.
	Refresh bool
}

func rejected(format string, a ...any) Result {
	return Result{Status: "rejected", Output: fmt.Sprintf(format, a...)}
}

func failed(format string, a ...any) Result {
	return Result{Status: "failed", Output: fmt.Sprintf(format, a...)}
}

// Manager executes endpoint actions. The zero value is not usable: use New
// (or fill the interfaces in tests).
type Manager struct {
	Paths    state.Paths
	Services ServiceControl
	Registry Registry
	Programs Programs
	// RemoteActive reports whether an attended remote session is running
	// (TermService is protected while one is).
	RemoteActive func() bool
	// AgentDir is the directory of the running agent binary (never uninstalled).
	AgentDir string
	// SystemRoot is %SystemRoot% (for msiexec.exe).
	SystemRoot string

	// Waits; shortened in tests.
	ServiceWait   time.Duration
	VerifyWait    time.Duration
	PollEvery     time.Duration
	UninstallTime time.Duration

	mu sync.Mutex
}

// supportedOS: tests run the Windows logic on every OS with fakes.
var supportedOS = platformSupported

// Supported reports whether this OS has endpoint actions.
func Supported() bool { return platformSupported }

// New returns a Manager with the platform's real backends.
func New(p state.Paths) *Manager {
	m := &Manager{Paths: p, ServiceWait: 60 * time.Second, VerifyWait: 2 * time.Minute, PollEvery: time.Second,
		UninstallTime: 30 * time.Minute, SystemRoot: os.Getenv("SystemRoot")}
	if m.SystemRoot == "" {
		m.SystemRoot = `C:\Windows`
	}
	if exe, err := os.Executable(); err == nil {
		m.AgentDir = filepath.Dir(exe)
	}
	m.Services, m.Registry, m.Programs = platformBackends()
	return m
}

// ValidateParams checks a command's parameters (the agent's own copy of the
// server-side validation in backend/app/services/endpoint_actions.py).
func ValidateParams(c model.Command) error {
	var err error
	switch c.Type {
	case ManageService:
		_, err = ParseServiceParams(c.Params)
	case UninstallSoftware:
		_, err = ParseUninstallParams(c.Params)
	}
	return err
}

// Execute runs an already validated command.
func (m *Manager) Execute(ctx context.Context, c model.Command) Result {
	if !supportedOS {
		return Result{Status: "rejected", Output: ErrUnsupported.Error(), Data: map[string]any{"error_code": "ERR_UNSUPPORTED_OS"}}
	}
	m.mu.Lock() // one endpoint action at a time
	defer m.mu.Unlock()
	switch c.Type {
	case ManageService:
		p, err := ParseServiceParams(c.Params)
		if err != nil {
			return rejected("%v", err)
		}
		return m.manageService(ctx, c.ID, p)
	case UninstallSoftware:
		p, err := ParseUninstallParams(c.Params)
		if err != nil {
			return rejected("%v", err)
		}
		return m.uninstall(ctx, p)
	case BlockUSBStorage:
		return m.blockUSB(c.ID)
	case UnblockUSBStorage:
		return m.unblockUSB()
	}
	return rejected("%s is not an endpoint action", c.Type)
}

// ----------------------------------------------------------------------------- saved values

type savedService struct {
	Name      string    `json:"name"`
	StartType string    `json:"start_type"`
	SavedAt   time.Time `json:"saved_at"`
	CommandID string    `json:"command_id,omitempty"`
}

type savedValue struct {
	Key    string `json:"key"`
	Name   string `json:"name"`
	Exists bool   `json:"exists"`
	Value  uint32 `json:"value"`
}

type savedUSB struct {
	SavedAt   time.Time    `json:"saved_at"`
	CommandID string       `json:"command_id,omitempty"`
	Values    []savedValue `json:"values"`
	// CreatedKeys were created by the block and are removed again (if empty) on unblock.
	CreatedKeys []string `json:"created_keys,omitempty"`
}

type saved struct {
	// Services by lower-case service name.
	Services map[string]savedService `json:"services,omitempty"`
	USB      *savedUSB               `json:"usb,omitempty"`
}

func (m *Manager) load() (*saved, error) {
	s := &saved{}
	b, err := os.ReadFile(filepath.Join(m.Paths.StateDir, FileName))
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, fmt.Errorf("%s is corrupt: %w", FileName, err)
	}
	return s, nil
}

func (m *Manager) store(s *saved) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return state.WriteFile(m.Paths, FileName, b)
}

// ----------------------------------------------------------------------------- helpers

var serviceNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.$@{}~+ -]{0,255}$`)

func str(p map[string]any, k string) (string, bool) {
	v, ok := p[k]
	if !ok || v == nil {
		return "", false
	}
	s, ok := v.(string)
	return strings.TrimSpace(s), ok
}

func sameFold(a, b string) bool { return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b)) }

// wait polls cond until it is true or the wait is over.
func (m *Manager) wait(ctx context.Context, d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for {
		if cond() {
			return true
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return false
		}
		t := time.NewTimer(m.PollEvery)
		select {
		case <-ctx.Done():
			t.Stop()
			return false
		case <-t.C:
		}
	}
}
