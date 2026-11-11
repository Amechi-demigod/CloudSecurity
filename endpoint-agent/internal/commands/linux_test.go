package commands

import (
	"errors"
	"strings"
	"testing"
)

// The other tests exercise the cross-platform behaviour (Windows / macOS
// command set) whatever OS the test runs on; the Linux tests set goos explicitly.
func init() { goos = "windows" }

func TestLinuxRefusesDesktopCommands(t *testing.T) {
	goos = "linux"
	defer func() { goos = "windows" }()
	for _, typ := range []string{LockDevice, EnableLostMode, DisableLostMode, WipeDevice, RunScript, IsolateHost, RestoreHost,
		StartRemoteSession, ManageService, UninstallSoftware, BlockUSBStorage, UnblockUSBStorage, ScanOSUpdates} {
		err := Validate(cmd(typ, nil), "dev", now)
		if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "not supported on Linux servers") {
			t.Errorf("%s: %v", typ, err)
		}
	}
	for _, typ := range []string{RecheckPosture, CollectLogs, RestartAgent, CheckForUpdate} {
		if err := Validate(cmd(typ, nil), "dev", now); err != nil {
			t.Errorf("%s must work on Linux: %v", typ, err)
		}
	}
	if err := Validate(cmd(UpdateCheckInInterval, map[string]any{"interval_seconds": float64(900)}), "dev", now); err != nil {
		t.Errorf("interval: %v", err)
	}
	if msg := UnsupportedOn("windows", LockDevice); msg != "" {
		t.Errorf("windows: %q", msg)
	}
}
