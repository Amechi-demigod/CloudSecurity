//go:build windows

package commands

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32                   = windows.NewLazySystemDLL("user32.dll")
	procLockWorkStation      = user32.NewProc("LockWorkStation")
	wtsapi32                 = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSDisconnectSession = wtsapi32.NewProc("WTSDisconnectSession")
)

const wtsActive = 0

// Lock locks every active interactive session.
//
// LockWorkStation only works when called from a process inside the user's
// interactive session; the service runs as LocalSystem in session 0. So for
// each active session we obtain the user's token (WTSQueryUserToken, allowed
// for LocalSystem) and start `rundll32.exe user32.dll,LockWorkStation` in that
// session's interactive desktop. If that fails, the session is disconnected
// (WTSDisconnectSession), which also returns it to the sign-in screen without
// logging the user off. When the agent runs interactively (not as a service),
// LockWorkStation is called directly.
func Lock(ctx context.Context) (string, error) {
	if !isLocalSystem() {
		r, _, err := procLockWorkStation.Call()
		if r == 0 {
			return "", fmt.Errorf("LockWorkStation: %v", err)
		}
		return "workstation locked (interactive agent)", nil
	}
	sessions, err := activeSessions()
	if err != nil {
		return "", err
	}
	if len(sessions) == 0 {
		return "", errors.New("no active interactive session; nothing to lock")
	}
	var out []string
	var failed int
	for _, id := range sessions {
		if err := lockSession(id); err == nil {
			out = append(out, fmt.Sprintf("session %d: locked (LockWorkStation)", id))
			continue
		} else if r, _, derr := procWTSDisconnectSession.Call(0, uintptr(id), 1); r != 0 {
			out = append(out, fmt.Sprintf("session %d: disconnected to the sign-in screen (LockWorkStation failed: %v)", id, err))
		} else {
			failed++
			out = append(out, fmt.Sprintf("session %d: FAILED (%v; disconnect: %v)", id, err, derr))
		}
	}
	msg := strings.Join(out, "\n")
	if failed == len(sessions) {
		return msg, errors.New("could not lock any session")
	}
	return msg, nil
}

func isLocalSystem() bool {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false
	}
	return tu.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
}

func activeSessions() ([]uint32, error) {
	var info *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &info, &count); err != nil {
		return nil, fmt.Errorf("WTSEnumerateSessions: %w", err)
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(info)))
	var ids []uint32
	for _, s := range unsafe.Slice(info, count) {
		if s.State == wtsActive && s.SessionID != 0 {
			ids = append(ids, s.SessionID)
		}
	}
	return ids, nil
}

func lockSession(session uint32) error {
	var tok windows.Token
	if err := windows.WTSQueryUserToken(session, &tok); err != nil {
		return fmt.Errorf("WTSQueryUserToken: %w", err)
	}
	defer tok.Close()
	var env *uint16
	if err := windows.CreateEnvironmentBlock(&env, tok, false); err == nil {
		defer windows.DestroyEnvironmentBlock(env)
	}
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	exe := filepath.Join(root, "System32", "rundll32.exe")
	app, _ := windows.UTF16PtrFromString(exe)
	cmdline, _ := windows.UTF16PtrFromString(`"` + exe + `" user32.dll,LockWorkStation`)
	desktop, _ := windows.UTF16PtrFromString(`winsta0\default`)
	si := windows.StartupInfo{Desktop: desktop}
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation
	const createUnicodeEnvironment, createNoWindow = 0x00000400, 0x08000000
	if err := windows.CreateProcessAsUser(tok, app, cmdline, nil, nil, false,
		createUnicodeEnvironment|createNoWindow, env, nil, &si, &pi); err != nil {
		return fmt.Errorf("CreateProcessAsUser: %w", err)
	}
	defer windows.CloseHandle(pi.Thread)
	defer windows.CloseHandle(pi.Process)
	ev, err := windows.WaitForSingleObject(pi.Process, 15000)
	if err != nil || ev != windows.WAIT_OBJECT_0 {
		return fmt.Errorf("rundll32 did not finish: %v", err)
	}
	var code uint32
	if err := windows.GetExitCodeProcess(pi.Process, &code); err == nil && code != 0 {
		return fmt.Errorf("rundll32 exited with %d", code)
	}
	return nil
}
