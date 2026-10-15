//go:build !darwin && !windows

package service

import (
	"context"
	"errors"
)

var errUnsupported = errors.New("service install is only supported on Windows and macOS (see docs for running `cnapp-agent run` under systemd)")

// IsService is always false on this platform.
func IsService() bool { return false }

// RunService is unsupported here.
func RunService(func(ctx context.Context) error) error { return errUnsupported }

// Install is unsupported here.
func Install(Options) error { return errUnsupported }

// Uninstall is unsupported here.
func Uninstall() error { return errUnsupported }
