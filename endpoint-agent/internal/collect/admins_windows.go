//go:build windows

package collect

import (
	"context"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// LocalAdmin is one member of the local Administrators group.
type LocalAdmin struct {
	Name    string // local account name, when resolvable
	SID     string
	Local   bool // true if sid is in THIS MACHINE's account domain (see machineAccountDomainSID)
	Enabled bool // only meaningful when Local is true
}

var (
	advapi32                      = windows.NewLazySystemDLL("advapi32.dll")
	procLsaOpenPolicy             = advapi32.NewProc("LsaOpenPolicy")
	procLsaClose                  = advapi32.NewProc("LsaClose")
	procLsaQueryInformationPolicy = advapi32.NewProc("LsaQueryInformationPolicy")
	procLsaFreeMemory             = advapi32.NewProc("LsaFreeMemory")

	netapi32                    = windows.NewLazySystemDLL("netapi32.dll")
	procNetLocalGroupGetMembers = netapi32.NewProc("NetLocalGroupGetMembers")
)

const policyViewLocalInformation = 0x00000001

// lsaUnicodeString/lsaObjectAttributes mirror the LSA structs (not wrapped by
// golang.org/x/sys/windows); kept minimal and local to this file rather than
// importing internal/signin's copies, since collect must not depend on signin
// (the dependency runs the other way: signin already imports collect).
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

// policyAccountDomainInfo mirrors POLICY_ACCOUNT_DOMAIN_INFO.
type policyAccountDomainInfo struct {
	DomainName lsaUnicodeString
	DomainSid  *windows.SID
}

const policyAccountDomainInformation = 5

func lsaCheck(status uintptr) error {
	if uint32(status) == 0 {
		return nil
	}
	return syscall.Errno(uint32(status))
}

func lsaOpenPolicyLocal(access uint32) (windows.Handle, error) {
	var oa lsaObjectAttributes
	oa.Length = uint32(unsafe.Sizeof(oa))
	var handle windows.Handle
	r, _, _ := procLsaOpenPolicy.Call(0, uintptr(unsafe.Pointer(&oa)), uintptr(access), uintptr(unsafe.Pointer(&handle)))
	if err := lsaCheck(r); err != nil {
		return 0, fmt.Errorf("LsaOpenPolicy: %w", err)
	}
	return handle, nil
}

// machineAccountDomainSID returns this machine's local SAM account-domain
// SID string (e.g. S-1-5-21-<A>-<B>-<C>), via the documented
// LsaQueryInformationPolicy(PolicyAccountDomainInformation) call - not a
// hardcoded or guessed value, since it's unique per machine.
func machineAccountDomainSID() (string, error) {
	policy, err := lsaOpenPolicyLocal(policyViewLocalInformation)
	if err != nil {
		return "", err
	}
	defer func() { _, _, _ = procLsaClose.Call(uintptr(policy)) }()
	var buf *policyAccountDomainInfo
	r, _, _ := procLsaQueryInformationPolicy.Call(uintptr(policy), policyAccountDomainInformation, uintptr(unsafe.Pointer(&buf)))
	if err := lsaCheck(r); err != nil {
		return "", fmt.Errorf("LsaQueryInformationPolicy(PolicyAccountDomainInformation): %w", err)
	}
	defer func() { _, _, _ = procLsaFreeMemory.Call(uintptr(unsafe.Pointer(buf))) }()
	if buf.DomainSid == nil {
		return "", fmt.Errorf("LsaQueryInformationPolicy(PolicyAccountDomainInformation): no domain SID returned")
	}
	// Read the SID as a string while the LSA-owned buffer is still valid.
	return buf.DomainSid.String(), nil
}

// administratorsGroupName resolves the LOCALIZED name of the well-known
// BUILTIN\Administrators group (S-1-5-32-544) via LookupAccountSid, rather
// than assuming the English name "Administrators" (wrong on a non-English
// Windows install).
func administratorsGroupName() (string, error) {
	sid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return "", fmt.Errorf("resolving BUILTIN\\Administrators SID: %w", err)
	}
	var name [256]uint16
	nameLen := uint32(len(name))
	var domain [256]uint16
	domainLen := uint32(len(domain))
	var use uint32
	if err := windows.LookupAccountSid(nil, sid, &name[0], &nameLen, &domain[0], &domainLen, &use); err != nil {
		return "", fmt.Errorf("LookupAccountSid(BUILTIN\\Administrators): %w", err)
	}
	return windows.UTF16ToString(name[:nameLen]), nil
}

// localGroupMembersInfo1 mirrors LOCALGROUP_MEMBERS_INFO_1.
type localGroupMembersInfo1 struct {
	SID      *windows.SID
	SIDUsage uint32
	Name     *uint16
}

// userInfo2 mirrors USER_INFO_2 (level 2): enough to read usri2_flags
// (UF_ACCOUNTDISABLE) without the level-3-only fields this doesn't need.
// golang.org/x/sys/windows wraps NetUserGetInfo itself but only defines the
// level-10 result struct, which has no flags field.
type userInfo2 struct {
	Name         *uint16
	Password     *uint16
	PasswordAge  uint32
	Priv         uint32
	HomeDir      *uint16
	Comment      *uint16
	Flags        uint32
	ScriptPath   *uint16
	AuthFlags    uint32
	FullName     *uint16
	UsrComment   *uint16
	Parms        *uint16
	Workstations *uint16
	LastLogon    uint32
	LastLogoff   uint32
	AcctExpires  uint32
	MaxStorage   uint32
	UnitsPerWeek uint32
	LogonHours   *byte
	BadPwCount   uint32
	NumLogons    uint32
	LogonServer  *uint16
	CountryCode  uint32
	CodePage     uint32
}

const ufAccountDisable = 0x0002

// LocalAdministrators enumerates the local Administrators group (resolved by
// well-known SID S-1-5-32-544, not an assumed English name) via
// NetLocalGroupGetMembers, then classifies each member as local to THIS
// machine's SAM account domain by comparing its SID against
// machineAccountDomainSID() - never by assuming a NetUserGetInfo lookup by
// name "worked, so it must be local" (a same-named domain/Entra account could
// coincidentally resolve). A member whose SID is not in this machine's
// account domain - for example an Entra ID / Azure AD principal on an
// Entra-joined device - is reported with Local=false and is never miscounted
// as a usable local admin, and never treated as a fatal error (unlike
// PowerShell's Get-LocalGroupMember, which throws in exactly this situation).
func LocalAdministrators(ctx context.Context) ([]LocalAdmin, error) {
	groupNameStr, err := administratorsGroupName()
	if err != nil {
		return nil, err
	}
	groupName, err := windows.UTF16PtrFromString(groupNameStr)
	if err != nil {
		return nil, err
	}
	var buf *byte
	var entriesRead, totalEntries uint32
	r, _, _ := procNetLocalGroupGetMembers.Call(
		0, // local server
		uintptr(unsafe.Pointer(groupName)),
		1, // level 1: LOCALGROUP_MEMBERS_INFO_1
		uintptr(unsafe.Pointer(&buf)),
		0xFFFFFFFF, // MAX_PREFERRED_LENGTH
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
		0,
	)
	if r != 0 {
		return nil, fmt.Errorf("NetLocalGroupGetMembers(%s): %w", groupNameStr, syscall.Errno(r))
	}
	defer func() { _ = windows.NetApiBufferFree(buf) }()

	// Fail-safe: if the machine's account domain can't be determined, no
	// member can be confirmed local - never silently treat everyone as local.
	domainSID, domainErr := machineAccountDomainSID()
	var domainPrefix string
	if domainErr == nil && domainSID != "" {
		domainPrefix = domainSID + "-"
	}

	entries := unsafe.Slice((*localGroupMembersInfo1)(unsafe.Pointer(buf)), entriesRead)
	out := make([]LocalAdmin, 0, len(entries))
	for _, e := range entries {
		a := LocalAdmin{Name: windows.UTF16PtrToString(e.Name), SID: e.SID.String()}
		if e.SIDUsage != windows.SidTypeUser {
			// A group (e.g. a nested domain/Entra group), not a single user
			// account: "enabled" doesn't apply, and it alone never satisfies
			// the local-admin check.
			out = append(out, a)
			continue
		}
		if domainPrefix == "" || !strings.HasPrefix(a.SID, domainPrefix) {
			// Not issued by this machine's local SAM domain: a domain/Entra
			// account, or locality simply couldn't be confirmed. Never local.
			out = append(out, a)
			continue
		}
		a.Local = true
		a.Enabled = localUserEnabled(a.Name)
		out = append(out, a)
	}
	return out, nil
}

// localUserEnabled reads UF_ACCOUNTDISABLE for a name already confirmed local
// by SID; a lookup failure here (renamed/raced account) just means "not
// confirmed enabled", not "not local" - locality was already established by SID.
func localUserEnabled(name string) bool {
	uname, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return false
	}
	var buf *byte
	if err := windows.NetUserGetInfo(nil, uname, 2, &buf); err != nil {
		return false
	}
	defer func() { _ = windows.NetApiBufferFree(buf) }()
	info := (*userInfo2)(unsafe.Pointer(buf))
	return info.Flags&ufAccountDisable == 0
}

// EnabledLocalAdminNames returns the names of local Administrators-group
// members that resolve to an ENABLED local SAM account: the fail-safe "would
// someone still be able to sign in as an admin" check for suspend-sign-in
// pre-flight. Entra/foreign principals and disabled accounts are excluded,
// never counted as present.
func EnabledLocalAdminNames(ctx context.Context) ([]string, error) {
	admins, err := LocalAdministrators(ctx)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, a := range admins {
		if a.Local && a.Enabled {
			names = append(names, a.Name)
		}
	}
	return names, nil
}
