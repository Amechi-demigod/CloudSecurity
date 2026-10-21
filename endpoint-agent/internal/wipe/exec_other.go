//go:build !windows

package wipe

import (
	"context"
	"errors"
	"runtime"
)

// Probe reports that remote wipe is unsupported on this OS.
func Probe(_ context.Context, optIn bool) Readiness {
	r := Readiness{OptIn: optIn, Supported: false}
	r.Finish()
	if runtime.GOOS == "darwin" {
		r.Detail = "remote wipe is not supported on macOS: erasing a Mac needs a real Apple MDM (EraseDevice)"
	}
	return r
}

// WMIExecutor does not exist outside Windows.
type WMIExecutor struct{}

// Invoke always fails outside Windows.
func (WMIExecutor) Invoke(context.Context, string) (string, error) {
	return "", errors.New("remote wipe is only supported on Windows")
}
