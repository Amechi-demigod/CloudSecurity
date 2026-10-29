//go:build windows

package collect

import (
	"context"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// LocalAdmin is one member of the local Administrators group.
type LocalAdmin struct {
	Name    string // local account name, when resolvable
	SID     string
	Local   bool // true if this resolved to a local SAM account we could query
	Enabled bool // only meaningful when Local is true
}

var (
	netapi32                    = windows.NewLazySystemDLL("netapi32.dll")
	procNetLocalGroupGetMembers = netapi32.NewProc("NetLocalGroupGetMembers")
)

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

// LocalAdministrators enumerates the local Administrators group (well-known
// SID S-1-5-32-544) by SID via NetLocalGroupGetMembers, then resolves each
// member's enabled/disabled status via NetUserGetInfo for local SAM accounts
// only. A member that is not a local SAM account - for example an Entra ID /
// Azure AD principal on an Entra-joined device - is reported with Local=false
// and is logged by the caller, never miscounted as a usable local admin and
// never treated as a fatal error (unlike PowerShell's Get-LocalGroupMember,
// which throws in exactly this situation).
func LocalAdministrators(ctx context.Context) ([]LocalAdmin, error) {
	groupName, err := windows.UTF16PtrFromString("Administrators")
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
		return nil, fmt.Errorf("NetLocalGroupGetMembers: %w", syscall.Errno(r))
	}
	defer func() { _ = windows.NetApiBufferFree(buf) }()

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
		enabled, local := localUserEnabled(a.Name)
		a.Local, a.Enabled = local, enabled
		out = append(out, a)
	}
	return out, nil
}

func localUserEnabled(name string) (enabled bool, local bool) {
	uname, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return false, false
	}
	var buf *byte
	if err := windows.NetUserGetInfo(nil, uname, 2, &buf); err != nil {
		// Not a local SAM account (e.g. an Entra/foreign principal resolved
		// to a bare name): skip, do not fail the whole enumeration.
		return false, false
	}
	defer func() { _ = windows.NetApiBufferFree(buf) }()
	info := (*userInfo2)(unsafe.Pointer(buf))
	return info.Flags&ufAccountDisable == 0, true
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
