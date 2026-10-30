//go:build !windows && !remote_fake

package remote

import (
	"context"
	"runtime"
)

// DefaultPlatform: remote sessions are Windows-only for now (a macOS helper
// with ScreenCaptureKit is future work, docs/DEVICE_MANAGEMENT.md). Every
// start fails cleanly with ERR_UNSUPPORTED_PLATFORM, which the server audits.
func DefaultPlatform() Platform { return unsupported{} }

type unsupported struct{}

func (unsupported) Preflight(context.Context) error {
	return Errorf(ErrUnsupportedPlatform, "remote sessions are not supported on %s yet (Windows only)", runtime.GOOS)
}

func (unsupported) Launch(context.Context, Params) (Helper, error) {
	return nil, Errorf(ErrUnsupportedPlatform, "remote sessions are not supported on %s yet", runtime.GOOS)
}

func (unsupported) Watch(context.Context) <-chan string { return nil }

func (unsupported) SendSAS() error {
	return Errorf(ErrUnsupportedPlatform, "Ctrl+Alt+Del is Windows only")
}
