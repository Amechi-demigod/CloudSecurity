//go:build windows

package service

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// Running the collector service as a group Managed Service Account (gMSA).
// The account needs "Log on as a service" (SeServiceLogonRight), which the
// service manager does not grant by itself, and - because a gMSA is not
// LocalSystem - the right to start / stop its own service (the self-update
// watchdog restarts it). Its state and program directories get an ACE for it
// in internal/state (SecureDirFor) and here (installDirFor).

var (
	advapi32               = windows.NewLazySystemDLL("advapi32.dll")
	procLsaOpenPolicy      = advapi32.NewProc("LsaOpenPolicy")
	procLsaAddAccountRight = advapi32.NewProc("LsaAddAccountRights")
	procLsaClose           = advapi32.NewProc("LsaClose")
	procLsaNtStatusToWin   = advapi32.NewProc("LsaNtStatusToWinError")
)

const (
	policyCreateAccount = 0x00000010
	policyLookupNames   = 0x00000800
)

type lsaObjectAttributes struct {
	Length                   uint32
	RootDirectory            uintptr
	ObjectName               uintptr
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

func ntErr(status uintptr) error {
	if status == 0 {
		return nil
	}
	code, _, _ := procLsaNtStatusToWin.Call(status)
	return windows.Errno(code)
}

// AccountSID resolves DOMAIN\name$ to its SID (needs a reachable DC).
func AccountSID(account string) (*windows.SID, error) {
	sid, _, _, err := windows.LookupSID("", account)
	if err != nil {
		return nil, fmt.Errorf("looking up %s (is it a gMSA installed on this computer?): %w", account, err)
	}
	return sid, nil
}

func grantServiceLogon(account string) error {
	sid, err := AccountSID(account)
	if err != nil {
		return err
	}
	var attrs lsaObjectAttributes
	attrs.Length = uint32(unsafe.Sizeof(attrs))
	var h uintptr
	st, _, _ := procLsaOpenPolicy.Call(0, uintptr(unsafe.Pointer(&attrs)), policyCreateAccount|policyLookupNames,
		uintptr(unsafe.Pointer(&h)))
	if err := ntErr(st); err != nil {
		return fmt.Errorf("LsaOpenPolicy: %w", err)
	}
	defer procLsaClose.Call(h) //nolint:errcheck
	right, err := windows.NewNTUnicodeString("SeServiceLogonRight")
	if err != nil {
		return err
	}
	st, _, _ = procLsaAddAccountRight.Call(h, uintptr(unsafe.Pointer(sid)), uintptr(unsafe.Pointer(right)), 1)
	if err := ntErr(st); err != nil {
		return fmt.Errorf("granting %s \"Log on as a service\": %w", account, err)
	}
	return nil
}

// allowSelfControl adds an ACE letting the service account query, start and
// stop this service (nothing else) to the default service DACL.
func allowSelfControl(s *mgr.Service, account string) error {
	sid, err := AccountSID(account)
	if err != nil {
		return err
	}
	sddl := "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)" +
		"(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;" + sid.String() + ")"
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if err := windows.SetSecurityInfo(s.Handle, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION, nil, nil,
		dacl, nil); err != nil {
		return fmt.Errorf("service permissions for %s: %w", account, err)
	}
	return nil
}

// allowInstallDir lets the gMSA replace its own binary (signed self-update)
// in its program folder; everything else stays as inherited from Program Files.
func allowInstallDir(dir, account string) error {
	sid, err := AccountSID(account)
	if err != nil {
		return err
	}
	cur, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	old, _, err := cur.DACL()
	if err != nil {
		return err
	}
	entries := []windows.EXPLICIT_ACCESS{{
		AccessPermissions: 0x1301bf, AccessMode: windows.GRANT_ACCESS,
		Inheritance: windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid)},
	}}
	merged, err := windows.ACLFromEntries(entries, old)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil,
		merged, nil)
}
