//go:build !windows && !darwin

package signin

import (
	"context"
	"encoding/json"
	"errors"
)

var errUnsupported = errors.New("suspend sign-in is not supported on this platform")

type otherBackend struct{}

func (otherBackend) Name() string { return "unsupported" }
func (otherBackend) CaptureLogonRestriction(context.Context) (json.RawMessage, error) {
	return nil, errUnsupported
}
func (otherBackend) ApplyLogonRestriction(context.Context, []string, json.RawMessage) (string, []string, error) {
	return "", nil, errUnsupported
}
func (otherBackend) ReapplyLogonRestriction(context.Context, []string, json.RawMessage) (string, []string, error) {
	return "", nil, errUnsupported
}
func (otherBackend) RestoreLogonRestriction(context.Context, json.RawMessage) error {
	return errUnsupported
}
func (otherBackend) VerifyStandardSignInBlocked(context.Context, []string) (bool, string, error) {
	return false, "", errUnsupported
}
func (otherBackend) VerifyStandardSignInWorks(context.Context, json.RawMessage) (bool, string, error) {
	return false, "", errUnsupported
}

type otherAdminProbe struct{}

func (otherAdminProbe) EnabledLocalAdmins(context.Context) ([]string, error) {
	return nil, errUnsupported
}

type otherSessionTerminator struct{}

func (otherSessionTerminator) SignOutNonAdmins(context.Context, []string) (string, error) {
	return "", errUnsupported
}

func platformBackend() Backend                     { return otherBackend{} }
func platformAdminProbe() AdminProbe               { return otherAdminProbe{} }
func platformLAPSProbe() LAPSProbe                 { return nil }
func platformSessionTerminator() SessionTerminator { return otherSessionTerminator{} }
