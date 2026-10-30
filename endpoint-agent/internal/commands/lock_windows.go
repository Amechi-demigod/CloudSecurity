//go:build windows

package commands

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/usersession"
)

var (
	user32                   = windows.NewLazySystemDLL("user32.dll")
	procLockWorkStation      = user32.NewProc("LockWorkStation")
	wtsapi32                 = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSDisconnectSession = wtsapi32.NewProc("WTSDisconnectSession")
)

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

func isLocalSystem() bool { return usersession.IsLocalSystem() }

func activeSessions() ([]uint32, error) { return usersession.ActiveSessions() }

func lockSession(session uint32) error {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	exe := filepath.Join(root, "System32", "rundll32.exe")
	p, err := usersession.Launch(session, exe, `"`+exe+`" user32.dll,LockWorkStation`, usersession.Options{NoWindow: true})
	if err != nil {
		return err
	}
	defer p.Close()
	code, err := p.Wait(15000)
	if err != nil {
		return fmt.Errorf("rundll32 did not finish: %v", err)
	}
	if code != 0 {
		return fmt.Errorf("rundll32 exited with %d", code)
	}
	return nil
}
