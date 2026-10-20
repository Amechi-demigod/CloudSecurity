// Package lostmode puts a device into "lost mode": a custom message and a
// contact phone number on the sign-in / lock screen, the interactive sessions
// locked (and re-locked while lost mode lasts), until an admin clears it.
// Exiting restores exactly the settings that were there before.
//
// What is possible without an MDM (docs/DEVICE_MANAGEMENT.md#lost-mode):
//
//   - Windows: the "interactive logon" legal notice (HKLM\...\Policies\System
//     LegalNoticeCaption / LegalNoticeText) is shown by Winlogon before the
//     credential prompt at every sign-in (after a restart, sign-out or "switch
//     user"). Windows 10/11 do not show it when unlocking a locked session, so
//     the message appears at the next sign-in. A domain GPO that sets the same
//     values wins at the next policy refresh.
//   - macOS: /Library/Preferences/com.apple.loginwindow LoginwindowText is the
//     "Show message when screen is locked" text: shown on the lock screen and the
//     login window. The FileVault unlock screen uses a copy on the Preboot
//     volume, refreshed with `diskutil apfs updatePreboot /` (best effort).
//     Locking uses `pmset displaysleepnow`, which only locks when the user
//     requires a password after sleep (see the lock_device notes).
package lostmode

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/state"
)

// FileName of the lost-mode record in the protected state directory.
const FileName = "lostmode.json"

// RelockInterval: while lost mode is active the agent locks any active session again this often.
const RelockInterval = 5 * time.Minute

// Notice is the platform's sign-in / lock-screen message. *Set is false when
// the value does not exist (so restoring deletes it instead of writing "").
type Notice struct {
	Caption    string `json:"caption"`
	CaptionSet bool   `json:"caption_set"`
	Text       string `json:"text"`
	TextSet    bool   `json:"text_set"`
}

// Backend reads and writes the platform notice.
type Backend interface {
	Get(ctx context.Context) (Notice, error)
	Set(ctx context.Context, n Notice) error
	// Restore writes back a Notice obtained from Get (deleting unset values).
	Restore(ctx context.Context, n Notice) error
	// Name describes the mechanism for result output.
	Name() string
}

// Record is persisted while lost mode is active.
type Record struct {
	Active   bool      `json:"active"`
	Message  string    `json:"message"`
	Phone    string    `json:"phone"`
	Since    time.Time `json:"since"`
	Previous Notice    `json:"previous"`
}

// Manager applies and clears lost mode.
type Manager struct {
	Paths   state.Paths
	Backend Backend
	Lock    func(ctx context.Context) (string, error)
	Now     func() time.Time
}

// New returns a Manager with the platform backend.
func New(p state.Paths, lock func(ctx context.Context) (string, error)) *Manager {
	return &Manager{Paths: p, Backend: platformBackend(), Lock: lock, Now: time.Now}
}

func (m *Manager) file() string { return filepath.Join(m.Paths.StateDir, FileName) }

// Load returns the current record (nil when not in lost mode).
func (m *Manager) Load() (*Record, error) {
	b, err := os.ReadFile(m.file())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r Record
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("corrupt %s: %w", m.file(), err)
	}
	if !r.Active {
		return nil, nil
	}
	return &r, nil
}

func (m *Manager) save(r *Record) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return state.WriteFile(m.Paths, FileName, b)
}

// Compose builds the notice shown on the device.
func Compose(message, phone string) Notice {
	msg := strings.TrimSpace(message)
	text := msg
	if phone = strings.TrimSpace(phone); phone != "" {
		text += "\r\n\r\nIf found, please call: " + phone
	}
	return Notice{Caption: "This device has been reported lost", CaptionSet: true, Text: text, TextSet: true}
}

// Enable sets the message and locks the sessions. Enabling again updates the
// message but keeps the originally saved previous notice.
func (m *Manager) Enable(ctx context.Context, message, phone string) (string, error) {
	rec, err := m.Load()
	if err != nil {
		return "", err
	}
	var out []string
	if rec == nil {
		prev, err := m.Backend.Get(ctx)
		if err != nil {
			return "", fmt.Errorf("reading the current %s: %w", m.Backend.Name(), err)
		}
		rec = &Record{Active: true, Since: m.Now().UTC(), Previous: prev}
	} else {
		out = append(out, "lost mode was already active; message updated")
	}
	rec.Message, rec.Phone = message, phone
	// Persist first: a crash after changing the notice must still be reversible.
	if err := m.save(rec); err != nil {
		return "", fmt.Errorf("saving the lost-mode record: %w", err)
	}
	if err := m.Backend.Set(ctx, Compose(message, phone)); err != nil {
		_ = os.Remove(m.file())
		return "", fmt.Errorf("setting the %s: %w", m.Backend.Name(), err)
	}
	out = append(out, "lost-mode message set ("+m.Backend.Name()+")")
	out = append(out, m.lockNow(ctx))
	return strings.Join(out, "\n"), nil
}

func (m *Manager) lockNow(ctx context.Context) string {
	if m.Lock == nil {
		return "session lock: not available"
	}
	lo, lerr := m.Lock(ctx)
	if lerr != nil {
		// Lost mode stays active even when nobody is signed in to lock.
		return "session lock: " + strings.TrimSpace(lo+" "+lerr.Error())
	}
	return "session lock: " + lo
}

// Disable restores the previous notice and removes the record.
func (m *Manager) Disable(ctx context.Context) (string, error) {
	rec, err := m.Load()
	if err != nil {
		return "", err
	}
	if rec == nil {
		return "lost mode was not active; nothing to restore", nil
	}
	if err := m.Backend.Restore(ctx, rec.Previous); err != nil {
		return "", fmt.Errorf("restoring the previous %s: %w", m.Backend.Name(), err)
	}
	if err := os.Remove(m.file()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	return "lost mode cleared; previous " + m.Backend.Name() + " restored", nil
}

// Relock locks the sessions again if lost mode is active (called periodically).
func (m *Manager) Relock(ctx context.Context) (bool, string) {
	rec, err := m.Load()
	if err != nil || rec == nil || m.Lock == nil {
		return false, ""
	}
	return true, m.lockNow(ctx)
}

// Status is reported with every check-in (posture check "lost_mode").
func (m *Manager) Status() map[string]any {
	rec, err := m.Load()
	if err != nil {
		return map[string]any{"active": false, "error": err.Error()}
	}
	if rec == nil {
		return map[string]any{"active": false}
	}
	return map[string]any{"active": true, "since": rec.Since.Format(time.RFC3339), "mechanism": m.Backend.Name()}
}
