//go:build windows

package signin

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Raw LSA policy calls: none of these are wrapped by golang.org/x/sys/windows
// (confirmed against the vendored package), so they follow the same
// lazy-DLL pattern internal/commands/lock_windows.go already uses for
// WTSDisconnectSession.
var (
	advapi32                              = windows.NewLazySystemDLL("advapi32.dll")
	procLsaOpenPolicy                     = advapi32.NewProc("LsaOpenPolicy")
	procLsaClose                          = advapi32.NewProc("LsaClose")
	procLsaAddAccountRights               = advapi32.NewProc("LsaAddAccountRights")
	procLsaRemoveAccountRights            = advapi32.NewProc("LsaRemoveAccountRights")
	procLsaEnumerateAccountRights         = advapi32.NewProc("LsaEnumerateAccountRights")
	procLsaEnumerateAccountsWithUserRight = advapi32.NewProc("LsaEnumerateAccountsWithUserRight")
	procLsaFreeMemory                     = advapi32.NewProc("LsaFreeMemory")
	procLsaNtStatusToWinError             = advapi32.NewProc("LsaNtStatusToWinError")
)

const (
	policyViewLocalInformation = 0x00000001
	policyCreateAccount        = 0x00000010
	// policyLookupNames is required by LsaEnumerateAccountsWithUserRight,
	// LsaAddAccountRights, LsaRemoveAccountRights and LsaEnumerateAccountRights
	// alike; every lsaOpenPolicy call in this package must include it or those
	// calls fail with access denied.
	policyLookupNames = 0x00000800
)

// NTSTATUS values LSA returns for "nothing found", not real errors.
const (
	statusObjectNameNotFound = 0xC0000034
	statusNoMoreEntries      = 0x8000001A
)

type lsaUnicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type lsaObjectAttributes struct {
	Length                   uint32
	RootDirectory            windows.Handle
	ObjectName               *lsaUnicodeString
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

// lsaEnumerationInformation mirrors LSA_ENUMERATION_INFORMATION.
type lsaEnumerationInformation struct {
	Sid *windows.SID
}

func newLSAString(s string) (lsaUnicodeString, error) {
	p, err := windows.UTF16PtrFromString(s)
	if err != nil {
		return lsaUnicodeString{}, err
	}
	n := uint16(len(s) * 2) // right names/SIDs here are always ASCII
	return lsaUnicodeString{Length: n, MaximumLength: n + 2, Buffer: p}, nil
}

func lsaCheck(status uintptr) error {
	if uint32(status) == 0 {
		return nil
	}
	e, _, _ := procLsaNtStatusToWinError.Call(status)
	return syscall.Errno(e)
}

func lsaOpenPolicy(access uint32) (windows.Handle, error) {
	var oa lsaObjectAttributes
	oa.Length = uint32(unsafe.Sizeof(oa))
	var handle windows.Handle
	r, _, _ := procLsaOpenPolicy.Call(
		0, // SystemName: NULL = local system
		uintptr(unsafe.Pointer(&oa)),
		uintptr(access),
		uintptr(unsafe.Pointer(&handle)),
	)
	if err := lsaCheck(r); err != nil {
		return 0, fmt.Errorf("LsaOpenPolicy: %w", err)
	}
	return handle, nil
}

func lsaClose(h windows.Handle) {
	_, _, _ = procLsaClose.Call(uintptr(h))
}

func lsaAddAccountRights(policy windows.Handle, sid *windows.SID, rights []string) error {
	us := make([]lsaUnicodeString, len(rights))
	for i, r := range rights {
		s, err := newLSAString(r)
		if err != nil {
			return err
		}
		us[i] = s
	}
	r, _, _ := procLsaAddAccountRights.Call(
		uintptr(policy),
		uintptr(unsafe.Pointer(sid)),
		uintptr(unsafe.Pointer(&us[0])),
		uintptr(len(us)),
	)
	if err := lsaCheck(r); err != nil {
		return fmt.Errorf("LsaAddAccountRights: %w", err)
	}
	return nil
}

func lsaRemoveAccountRights(policy windows.Handle, sid *windows.SID, rights []string) error {
	us := make([]lsaUnicodeString, len(rights))
	for i, r := range rights {
		s, err := newLSAString(r)
		if err != nil {
			return err
		}
		us[i] = s
	}
	r, _, _ := procLsaRemoveAccountRights.Call(
		uintptr(policy),
		uintptr(unsafe.Pointer(sid)),
		0, // AllRights=FALSE: remove only the named rights
		uintptr(unsafe.Pointer(&us[0])),
		uintptr(len(us)),
	)
	if err := lsaCheck(r); err != nil {
		return fmt.Errorf("LsaRemoveAccountRights: %w", err)
	}
	return nil
}

// lsaEnumerateAccountRights returns the rights held by sid (empty, not an
// error, when the account has none).
func lsaEnumerateAccountRights(policy windows.Handle, sid *windows.SID) ([]string, error) {
	var buf *lsaUnicodeString
	var count uint32
	r, _, _ := procLsaEnumerateAccountRights.Call(
		uintptr(policy),
		uintptr(unsafe.Pointer(sid)),
		uintptr(unsafe.Pointer(&buf)),
		uintptr(unsafe.Pointer(&count)),
	)
	if uint32(r) == statusObjectNameNotFound {
		return nil, nil
	}
	if err := lsaCheck(r); err != nil {
		return nil, fmt.Errorf("LsaEnumerateAccountRights: %w", err)
	}
	defer func() { _, _, _ = procLsaFreeMemory.Call(uintptr(unsafe.Pointer(buf))) }()
	entries := unsafe.Slice(buf, count)
	out := make([]string, count)
	for i, e := range entries {
		out[i] = windows.UTF16ToString(unsafe.Slice(e.Buffer, e.Length/2))
	}
	return out, nil
}

// lsaEnumerateAccountsWithUserRight returns the string SIDs of every account
// currently holding right (empty, not an error, when nobody holds it). This
// is the reverse of lsaEnumerateAccountRights: "who holds this right" rather
// than "what rights does this SID have" - the question suspend-sign-in
// actually needs, to snapshot and later restore the exact holder set.
func lsaEnumerateAccountsWithUserRight(policy windows.Handle, right string) ([]string, error) {
	us, err := newLSAString(right)
	if err != nil {
		return nil, err
	}
	var buf *lsaEnumerationInformation
	var count uint32
	r, _, _ := procLsaEnumerateAccountsWithUserRight.Call(
		uintptr(policy),
		uintptr(unsafe.Pointer(&us)),
		uintptr(unsafe.Pointer(&buf)),
		uintptr(unsafe.Pointer(&count)),
	)
	if s := uint32(r); s == statusNoMoreEntries || s == statusObjectNameNotFound {
		return nil, nil
	}
	if err := lsaCheck(r); err != nil {
		return nil, fmt.Errorf("LsaEnumerateAccountsWithUserRight(%s): %w", right, err)
	}
	defer func() { _, _, _ = procLsaFreeMemory.Call(uintptr(unsafe.Pointer(buf))) }()
	entries := unsafe.Slice(buf, count)
	out := make([]string, count)
	for i, e := range entries {
		out[i] = e.Sid.String()
	}
	return out, nil
}
