//go:build !windows

package actions

// Endpoint actions are Windows only in this version: Execute answers
// "unsupported on this OS" and check-ins report no services / USB state.
const platformSupported = false

func platformBackends() (ServiceControl, Registry, Programs) { return nil, nil, nil }
