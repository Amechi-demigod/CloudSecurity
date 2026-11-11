//go:build linux

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const systemctl = "/usr/bin/systemctl"

// packagedUnits are where the .deb / .rpm packages install their unit file.
var packagedUnits = []string{"/usr/lib/systemd/system/" + SystemdUnitName, "/lib/systemd/system/" + SystemdUnitName}

// IsService reports whether the process was started as a Windows service
// (never on Linux: systemd runs `cnapp-agent run` like a normal process).
func IsService() bool { return false }

// RunService is unused on Linux.
func RunService(func(ctx context.Context) error) error { return errors.New("not a Windows service") }

func sc(args ...string) error {
	out, err := exec.Command(systemctl, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %v %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func packagedUnit() bool {
	for _, p := range packagedUnits {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// Install registers and starts the systemd service. With the .deb / .rpm the
// unit already exists (the package enables it); `cnapp-agent install` is for a
// standalone binary: it copies it to /usr/local/bin, writes the unit and
// starts it.
func Install(o Options) error {
	if os.Geteuid() != 0 {
		return errors.New("install must run as root (sudo)")
	}
	if _, err := os.Stat(systemctl); err != nil {
		return errors.New("systemd was not found: the Linux agent runs as a systemd service (or run `cnapp-agent run` under your own supervisor)")
	}
	if !packagedUnit() {
		bin := PackageBinaryPath
		if _, err := os.Stat(bin); err != nil {
			bin = LocalBinaryPath
			exe, err := os.Executable()
			if err != nil {
				return err
			}
			if err := copyFile(exe, bin, 0o755); err != nil {
				return err
			}
		}
		if err := os.WriteFile(SystemdUnitPath, []byte(SystemdUnit(bin, serviceArgs(o))), 0o644); err != nil {
			return err
		}
	}
	if err := sc("daemon-reload"); err != nil {
		return err
	}
	return sc("enable", "--now", SystemdUnitName)
}

// Restart restarts the service with the binary now in place (no-block: the
// agent is usually the process asking, and systemd stops it as part of the restart).
func Restart() error { return sc("restart", "--no-block", SystemdUnitName) }

// ManagedByServiceManager reports whether systemd started this process
// (it sets INVOCATION_ID for every service it runs).
func ManagedByServiceManager() bool { return os.Getenv("INVOCATION_ID") != "" }

// InstalledBinaryPath is the binary the unit runs.
func InstalledBinaryPath() string {
	if _, err := os.Stat(PackageBinaryPath); err == nil {
		return PackageBinaryPath
	}
	return LocalBinaryPath
}

// Uninstall stops and disables the service. A unit written by `install` and a
// binary copied by it are removed; the packaged unit and binary belong to the
// package (apt remove / dnf remove cnapp-agent).
func Uninstall() error {
	if os.Geteuid() != 0 {
		return errors.New("uninstall must run as root (sudo)")
	}
	_ = sc("disable", "--now", SystemdUnitName)
	for _, p := range []string{SystemdUnitPath, LocalBinaryPath} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	removeUpdateLeftovers(LocalBinaryPath)
	removeUpdateLeftovers(PackageBinaryPath)
	_ = sc("daemon-reload")
	return nil
}

// ConfigureRecovery is a no-op outside Windows (systemd Restart=always restarts the agent).
func ConfigureRecovery() error { return nil }
