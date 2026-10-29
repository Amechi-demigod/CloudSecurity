//go:build windows

package signin

import (
	"context"

	"golang.org/x/sys/windows/registry"
)

// winLAPSProbe reports Windows LAPS configuration by reading POLICY/CONFIG
// registry values only. It must never read, decrypt, cache or transmit an
// actual LAPS password: the password is an Active Directory attribute
// (ms-Mcs-AdmPwd / msLAPS-Password) or escrowed to Entra ID, never a
// registry value this probe touches, and nothing in this file calls a
// password-retrieval API (there is no PowerShell/WMI call here at all).
//
// NEEDS VERIFICATION against a real LAPS deployment before being relied on:
// these are Microsoft's documented policy registry locations as of this
// writing for legacy LAPS (the original on-prem AdmPwd GPO) and Windows LAPS
// (the client built into Windows 10/11, configured via GPO or MDM/CSP).
type winLAPSProbe struct{}

const (
	windowsLAPSPolicyKey = `SOFTWARE\Microsoft\Policies\LAPS`
	legacyLAPSPolicyKey  = `SOFTWARE\Policies\Microsoft Services\AdmPwd`
)

func (winLAPSProbe) Status(ctx context.Context) (LAPSStatus, error) {
	// Windows LAPS (modern, built-in): BackupDirectory 0=disabled, 1=Entra ID, 2=Active Directory.
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, windowsLAPSPolicyKey, registry.QUERY_VALUE); err == nil {
		defer k.Close()
		if backupDir, _, err := k.GetIntegerValue("BackupDirectory"); err == nil {
			entra := backupDir == 1
			return LAPSStatus{
				Configured: backupDir != 0, Source: "windows_laps_gpo", BackupToEntraID: &entra,
				Detail: "Windows LAPS policy present (BackupDirectory)",
			}, nil
		}
	}
	// Legacy LAPS (the original on-prem AdmPwd GPO): no Entra ID backup option.
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, legacyLAPSPolicyKey, registry.QUERY_VALUE); err == nil {
		defer k.Close()
		if enabled, _, err := k.GetIntegerValue("AdmPwdEnabled"); err == nil {
			entra := false
			return LAPSStatus{
				Configured: enabled != 0, Source: "legacy_laps", BackupToEntraID: &entra,
				Detail: "legacy LAPS policy present (AdmPwdEnabled); legacy LAPS has no Entra ID backup option",
			}, nil
		}
	}
	return LAPSStatus{Configured: false, Detail: "no LAPS policy found"}, nil
}
