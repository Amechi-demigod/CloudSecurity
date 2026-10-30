//go:build windows

package signin

import (
	"context"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/usersession"
)

// wtsapi32 has its own lazy-DLL handle here, independent of
// internal/commands' (different package); WTSLogoffSession and
// WTSQuerySessionInformationW aren't wrapped by golang.org/x/sys/windows.
var (
	wtsapi32                        = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSLogoffSession            = wtsapi32.NewProc("WTSLogoffSession")
	procWTSQuerySessionInformationW = wtsapi32.NewProc("WTSQuerySessionInformationW")
	procWTSFreeMemory               = wtsapi32.NewProc("WTSFreeMemory")
)

const wtsUserName = 5 // WTS_INFO_CLASS.WTSUserName

func activeSessions() ([]uint32, error) { return usersession.ActiveSessions() }

func sessionOwner(session uint32) string {
	var buf *uint16
	var n uint32
	r, _, _ := procWTSQuerySessionInformationW.Call(0, uintptr(session), wtsUserName,
		uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&n)))
	if r == 0 || buf == nil {
		return ""
	}
	defer func() { _, _, _ = procWTSFreeMemory.Call(uintptr(unsafe.Pointer(buf))) }()
	return windows.UTF16PtrToString(buf)
}

func isAdminOwner(owner string, adminNames []string) bool {
	bare := owner
	if i := strings.LastIndexByte(owner, '\\'); i >= 0 {
		bare = owner[i+1:]
	}
	for _, a := range adminNames {
		if strings.EqualFold(a, owner) || strings.EqualFold(a, bare) {
			return true
		}
	}
	return false
}

type winSessionTerminator struct{}

// SignOutNonAdmins signs out every active interactive session not owned by
// one of adminNames (case-insensitive, domain-prefix-tolerant), via
// WTSLogoffSession. Sessions owned by an admin are left untouched.
func (winSessionTerminator) SignOutNonAdmins(ctx context.Context, adminNames []string) (string, error) {
	sessions, err := activeSessions()
	if err != nil {
		return "", err
	}
	if len(sessions) == 0 {
		return "no active interactive session", nil
	}
	var out []string
	for _, id := range sessions {
		owner := sessionOwner(id)
		if owner == "" {
			out = append(out, fmt.Sprintf("session %d: no owner found, skipped", id))
			continue
		}
		if isAdminOwner(owner, adminNames) {
			out = append(out, fmt.Sprintf("session %d (%s): local admin session, not signed out", id, owner))
			continue
		}
		r, _, err := procWTSLogoffSession.Call(0, uintptr(id), 1)
		if r == 0 {
			out = append(out, fmt.Sprintf("session %d (%s): FAILED to sign out (%v)", id, owner, err))
		} else {
			out = append(out, fmt.Sprintf("session %d (%s): signed out", id, owner))
		}
	}
	return strings.Join(out, "\n"), nil
}
