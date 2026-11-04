//go:build windows

package main

import (
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/service"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/state"
)

// setServiceAccountSID: running as a gMSA (not LocalSystem), the state
// directory DACL must keep granting this account access (internal/state).
func setServiceAccountSID() {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return
	}
	if sid := u.User.Sid; !sid.IsWellKnown(windows.WinLocalSystemSid) && !sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		if service.IsService() {
			state.ServiceAccountSID = sid.String()
		}
	}
}

func accountSID(account string) (string, error) {
	sid, err := service.AccountSID(account)
	if err != nil {
		return "", err
	}
	return sid.String(), nil
}

func machineGUID() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`,
		registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, _ := k.GetStringValue("MachineGuid")
	return v
}
