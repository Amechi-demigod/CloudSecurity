//go:build windows

package signin

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
)

// The two allow rights that gate interactive sign-in. Suspending sign-in
// restricts these to BUILTIN\Administrators (plus kept service/virtual
// accounts) rather than adding a deny right: a deny right on BUILTIN\Users
// would also deny Administrators, since admin tokens include BUILTIN\Users by
// default (Authenticated Users/INTERACTIVE are members of Users), and Windows
// deny rights override allow rights.
const (
	rightInteractiveLogon       = "SeInteractiveLogonRight"
	rightRemoteInteractiveLogon = "SeRemoteInteractiveLogonRight"
	denyInteractiveLogon        = "SeDenyInteractiveLogonRight"
	denyRemoteInteractiveLogon  = "SeDenyRemoteInteractiveLogonRight"
)

var logonRights = []string{rightInteractiveLogon, rightRemoteInteractiveLogon}

// isServiceVirtualPrincipal reports whether sid is a built-in service or
// virtual account that must keep its logon rights untouched: NT SERVICE
// (S-1-5-80-*), Window Manager (S-1-5-90-*), Font Driver Host (S-1-5-96-*).
// Classified by SID prefix, not by (localized) name.
func isServiceVirtualPrincipal(sid string) bool {
	for _, prefix := range []string{"S-1-5-80-", "S-1-5-90-", "S-1-5-96-"} {
		if strings.HasPrefix(sid, prefix) {
			return true
		}
	}
	return false
}

// winLogonSnapshot is the Windows-specific Snapshot.LogonRestriction payload:
// the exact holders of each right before any change.
type winLogonSnapshot struct {
	Holders map[string][]string `json:"holders"`
}

func administratorsSID() (*windows.SID, error) {
	return windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
}

// reconcileHolders makes right's current holder set exactly want (adds
// missing SIDs, removes extra ones). Driving Apply/Restore by diffing against
// a target set, rather than tracking what was individually removed/added,
// keeps both operations idempotent and self-correcting even if interrupted.
func reconcileHolders(policy windows.Handle, right string, want []string) error {
	current, err := lsaEnumerateAccountsWithUserRight(policy, right)
	if err != nil {
		return err
	}
	wantSet := map[string]bool{}
	for _, s := range want {
		wantSet[s] = true
	}
	curSet := map[string]bool{}
	for _, s := range current {
		curSet[s] = true
	}
	for _, s := range current {
		if wantSet[s] {
			continue
		}
		sid, err := windows.StringToSid(s)
		if err != nil {
			return fmt.Errorf("parsing SID %s: %w", s, err)
		}
		if err := lsaRemoveAccountRights(policy, sid, []string{right}); err != nil {
			return fmt.Errorf("removing %s from %s: %w", right, s, err)
		}
	}
	for _, s := range want {
		if curSet[s] {
			continue
		}
		sid, err := windows.StringToSid(s)
		if err != nil {
			return fmt.Errorf("parsing SID %s: %w", s, err)
		}
		if err := lsaAddAccountRights(policy, sid, []string{right}); err != nil {
			return fmt.Errorf("granting %s to %s: %w", right, s, err)
		}
	}
	return nil
}

type winBackend struct{}

func (winBackend) Name() string {
	return "Windows interactive logon rights (SeInteractiveLogonRight / SeRemoteInteractiveLogonRight)"
}

func (winBackend) CaptureLogonRestriction(ctx context.Context) (json.RawMessage, error) {
	policy, err := lsaOpenPolicy(policyViewLocalInformation | policyLookupNames)
	if err != nil {
		return nil, err
	}
	defer lsaClose(policy)
	snap := winLogonSnapshot{Holders: map[string][]string{}}
	for _, right := range logonRights {
		holders, err := lsaEnumerateAccountsWithUserRight(policy, right)
		if err != nil {
			return nil, fmt.Errorf("reading current holders of %s: %w", right, err)
		}
		snap.Holders[right] = holders
	}
	return json.Marshal(snap)
}

func (b winBackend) ApplyLogonRestriction(ctx context.Context, adminNames []string, previous json.RawMessage) (string, error) {
	var snap winLogonSnapshot
	if err := json.Unmarshal(previous, &snap); err != nil {
		return "", fmt.Errorf("corrupt logon-restriction snapshot: %w", err)
	}
	policy, err := lsaOpenPolicy(policyViewLocalInformation | policyCreateAccount | policyLookupNames)
	if err != nil {
		return "", err
	}
	defer lsaClose(policy)

	adminSID, err := administratorsSID()
	if err != nil {
		return "", fmt.Errorf("resolving BUILTIN\\Administrators: %w", err)
	}
	adminSIDStr := adminSID.String()

	var kept []string
	for _, right := range logonRights {
		want := []string{adminSIDStr}
		for _, h := range snap.Holders[right] {
			if isServiceVirtualPrincipal(h) {
				want = append(want, h)
				kept = append(kept, h)
			}
		}
		if err := reconcileHolders(policy, right, want); err != nil {
			applyErr := fmt.Errorf("restricting %s: %w", right, err)
			if rerr := b.restoreWithPolicy(policy, snap); rerr != nil {
				return "", fmt.Errorf("%w (rollback also failed: %v)", applyErr, rerr)
			}
			return "", &RolledBackError{Err: applyErr}
		}
	}

	ok, detail, err := b.verifyRestricted(policy, adminSIDStr, snap)
	if err != nil {
		verifyErr := fmt.Errorf("verifying the restriction: %w", err)
		if rerr := b.restoreWithPolicy(policy, snap); rerr != nil {
			return "", fmt.Errorf("%w (rollback also failed: %v)", verifyErr, rerr)
		}
		return "", &RolledBackError{Err: verifyErr}
	}
	if !ok {
		safetyErr := fmt.Errorf("safety check failed: %s", detail)
		if rerr := b.restoreWithPolicy(policy, snap); rerr != nil {
			return "", fmt.Errorf("%w (rollback also failed: %v)", safetyErr, rerr)
		}
		return "", &RolledBackError{Err: safetyErr}
	}

	out := fmt.Sprintf("logon rights restricted to BUILTIN\\Administrators on both rights; %d built-in service/virtual "+
		"account(s) left untouched", len(uniqueStrings(kept)))
	return out, nil
}

func (winBackend) restoreWithPolicy(policy windows.Handle, snap winLogonSnapshot) error {
	for right, holders := range snap.Holders {
		if err := reconcileHolders(policy, right, holders); err != nil {
			return err
		}
	}
	return nil
}

func (b winBackend) RestoreLogonRestriction(ctx context.Context, previous json.RawMessage) error {
	var snap winLogonSnapshot
	if err := json.Unmarshal(previous, &snap); err != nil {
		return fmt.Errorf("corrupt logon-restriction snapshot: %w", err)
	}
	policy, err := lsaOpenPolicy(policyViewLocalInformation | policyCreateAccount | policyLookupNames)
	if err != nil {
		return err
	}
	defer lsaClose(policy)
	return b.restoreWithPolicy(policy, snap)
}

// verifyRestricted confirms, for both rights, that only BUILTIN\Administrators
// and kept service/virtual accounts hold them, that BUILTIN\Administrators
// does hold both, and that no deny-right variant has been separately applied
// to BUILTIN\Administrators (defense in depth; this backend never applies a
// deny right itself, but a GPO or another tool might).
func (winBackend) verifyRestricted(policy windows.Handle, adminSIDStr string, snap winLogonSnapshot) (bool, string, error) {
	for _, right := range logonRights {
		holders, err := lsaEnumerateAccountsWithUserRight(policy, right)
		if err != nil {
			return false, "", err
		}
		hasAdmin := false
		for _, h := range holders {
			if h == adminSIDStr {
				hasAdmin = true
				continue
			}
			if isServiceVirtualPrincipal(h) {
				continue
			}
			return false, fmt.Sprintf("%s is unexpectedly held by %s", right, h), nil
		}
		if !hasAdmin {
			return false, fmt.Sprintf("BUILTIN\\Administrators does not hold %s after applying the restriction", right), nil
		}
	}
	adminSID, err := windows.StringToSid(adminSIDStr)
	if err != nil {
		return false, "", err
	}
	denyRights, err := lsaEnumerateAccountRights(policy, adminSID)
	if err != nil {
		return false, "", err
	}
	for _, r := range denyRights {
		if r == denyInteractiveLogon || r == denyRemoteInteractiveLogon {
			return false, fmt.Sprintf("BUILTIN\\Administrators unexpectedly holds %s", r), nil
		}
	}
	return true, "BUILTIN\\Administrators holds both logon rights; no deny right applies to it", nil
}

func (winBackend) VerifyStandardSignInBlocked(ctx context.Context, adminNames []string) (bool, string, error) {
	policy, err := lsaOpenPolicy(policyViewLocalInformation | policyLookupNames)
	if err != nil {
		return false, "", err
	}
	defer lsaClose(policy)
	adminSID, err := administratorsSID()
	if err != nil {
		return false, "", err
	}
	adminSIDStr := adminSID.String()
	for _, right := range logonRights {
		holders, err := lsaEnumerateAccountsWithUserRight(policy, right)
		if err != nil {
			return false, "", err
		}
		for _, h := range holders {
			if h != adminSIDStr && !isServiceVirtualPrincipal(h) {
				return false, fmt.Sprintf("%s is still held by %s", right, h), nil
			}
		}
	}
	return true, "only BUILTIN\\Administrators (and built-in service/virtual accounts) hold the interactive logon rights", nil
}

func (winBackend) VerifyStandardSignInWorks(ctx context.Context, previous json.RawMessage) (bool, string, error) {
	var snap winLogonSnapshot
	if err := json.Unmarshal(previous, &snap); err != nil {
		return false, "", err
	}
	policy, err := lsaOpenPolicy(policyViewLocalInformation | policyLookupNames)
	if err != nil {
		return false, "", err
	}
	defer lsaClose(policy)
	for _, right := range logonRights {
		holders, err := lsaEnumerateAccountsWithUserRight(policy, right)
		if err != nil {
			return false, "", err
		}
		want := map[string]bool{}
		for _, h := range snap.Holders[right] {
			want[h] = true
		}
		got := map[string]bool{}
		for _, h := range holders {
			got[h] = true
		}
		if len(want) != len(got) {
			return false, fmt.Sprintf("%s holder set does not match the pre-suspend snapshot", right), nil
		}
		for h := range want {
			if !got[h] {
				return false, fmt.Sprintf("%s is missing a pre-suspend holder %s", right, h), nil
			}
		}
	}
	return true, "logon rights match the pre-suspend snapshot", nil
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func platformBackend() Backend                     { return winBackend{} }
func platformAdminProbe() AdminProbe               { return winAdminProbe{} }
func platformLAPSProbe() LAPSProbe                 { return winLAPSProbe{} }
func platformSessionTerminator() SessionTerminator { return winSessionTerminator{} }
