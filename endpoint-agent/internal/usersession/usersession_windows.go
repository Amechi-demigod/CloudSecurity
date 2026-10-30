//go:build windows

// Package usersession reaches the signed-in user's desktop from the service
// (LocalSystem, session 0): enumerate interactive sessions, tell whether one
// is locked, and start a process in it with the user's token.
//
// Used by lock_device (internal/commands), Suspend sign-in (internal/signin)
// and the remote-session helper (internal/remote).
package usersession

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wtsapi32                        = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSQuerySessionInformationW = wtsapi32.NewProc("WTSQuerySessionInformationW")
	procWTSFreeMemory               = wtsapi32.NewProc("WTSFreeMemory")
	kernel32                        = windows.NewLazySystemDLL("kernel32.dll")
	procWTSGetActiveConsoleSession  = kernel32.NewProc("WTSGetActiveConsoleSessionId")
)

// WTS_CONNECTSTATE_CLASS / WTS_INFO_CLASS values used here.
const (
	wtsActive      = 0
	wtsUserName    = 5
	wtsDomainName  = 7
	wtsSessionInfo = 25 // WTSSessionInfoEx
	// WTSINFOEX_LEVEL1.SessionFlags
	wtsSessionStateLock = 0
	noSession           = 0xFFFFFFFF
)

// ErrNoSession: nobody is signed in interactively.
var ErrNoSession = errors.New("no active interactive session")

// ActiveSessions lists the ids of active (connected, signed-in) sessions other than session 0.
func ActiveSessions() ([]uint32, error) {
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

// Attended picks the session a remote session attaches to: the physical
// console's session when someone is signed in there, else the only active
// (e.g. RDP) session. Several remote sessions and no console user is
// ambiguous and refused.
func Attended() (uint32, error) {
	ids, err := ActiveSessions()
	if err != nil {
		return 0, err
	}
	if r, _, _ := procWTSGetActiveConsoleSession.Call(); uint32(r) != noSession {
		for _, id := range ids {
			if id == uint32(r) {
				return id, nil
			}
		}
	}
	switch len(ids) {
	case 0:
		return 0, ErrNoSession
	case 1:
		return ids[0], nil
	}
	return 0, fmt.Errorf("%w: %d remote sessions and nobody at the console", ErrNoSession, len(ids))
}

// wtsInfoExLevel1 is the start of WTSINFOEXW (Level, then WTSINFOEX_LEVEL1_W);
// only the fields read here.
type wtsInfoExLevel1 struct {
	Level        uint32
	SessionID    uint32
	SessionState uint32
	SessionFlags int32
}

// State reports whether `session` is still active and whether its screen is locked.
func State(session uint32) (active, locked bool, err error) {
	var info *wtsInfoExLevel1
	var n uint32
	r, _, e := procWTSQuerySessionInformationW.Call(0, uintptr(session), wtsSessionInfo,
		uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&n)))
	if r == 0 || info == nil {
		return false, false, fmt.Errorf("WTSQuerySessionInformation(%d): %v", session, e)
	}
	defer func() { _, _, _ = procWTSFreeMemory.Call(uintptr(unsafe.Pointer(info))) }()
	return info.SessionState == wtsActive, info.SessionFlags == wtsSessionStateLock, nil
}

func queryString(session uint32, class uintptr) string {
	var buf *uint16
	var n uint32
	r, _, _ := procWTSQuerySessionInformationW.Call(0, uintptr(session), class,
		uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&n)))
	if r == 0 || buf == nil {
		return ""
	}
	defer func() { _, _, _ = procWTSFreeMemory.Call(uintptr(unsafe.Pointer(buf))) }()
	return windows.UTF16PtrToString(buf)
}

// Owner is the user signed in to `session` ("DOMAIN\user", or "user"); "" if unknown.
func Owner(session uint32) string {
	user := queryString(session, wtsUserName)
	if user == "" {
		return ""
	}
	if dom := queryString(session, wtsDomainName); dom != "" {
		return dom + `\` + user
	}
	return user
}

// UserSID is the SID of the user signed in to `session`.
func UserSID(session uint32) (*windows.SID, error) {
	var tok windows.Token
	if err := windows.WTSQueryUserToken(session, &tok); err != nil {
		return nil, fmt.Errorf("WTSQueryUserToken: %w", err)
	}
	defer tok.Close()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return nil, err
	}
	return tu.User.Sid.Copy()
}

// Process is a process started in a user session.
type Process struct {
	Handle windows.Handle
	PID    uint32
	job    windows.Handle
}

// Close kills the process (if still running) and releases its handles. The
// Job object is created with KILL_ON_JOB_CLOSE, so even if the service dies
// without calling Close, Windows kills the process when the handle goes away.
func (p *Process) Close() error {
	if p == nil {
		return nil
	}
	if p.job != 0 {
		_ = windows.TerminateJobObject(p.job, 1)
		_ = windows.CloseHandle(p.job)
		p.job = 0
	}
	if p.Handle != 0 {
		_ = windows.TerminateProcess(p.Handle, 1)
		_ = windows.CloseHandle(p.Handle)
		p.Handle = 0
	}
	return nil
}

// Wait waits up to `ms` milliseconds for the process to exit and returns its exit code.
func (p *Process) Wait(ms uint32) (uint32, error) {
	ev, err := windows.WaitForSingleObject(p.Handle, ms)
	if err != nil || ev != windows.WAIT_OBJECT_0 {
		return 0, fmt.Errorf("process %d did not exit: %v", p.PID, err)
	}
	var code uint32
	if err := windows.GetExitCodeProcess(p.Handle, &code); err != nil {
		return 0, err
	}
	return code, nil
}

// Options for Launch.
type Options struct {
	// KillOnClose puts the process in a Job object that kills it when the
	// job handle is closed (Process.Close, or the service exiting).
	KillOnClose bool
	// NoWindow starts a console program without a console window.
	NoWindow bool
}

// Launch starts `exe` with `cmdline` (including argv[0]) on winsta0\default of
// `session`, as the signed-in user (WTSQueryUserToken: LocalSystem only).
func Launch(session uint32, exe, cmdline string, o Options) (*Process, error) {
	var tok windows.Token
	if err := windows.WTSQueryUserToken(session, &tok); err != nil {
		return nil, fmt.Errorf("WTSQueryUserToken: %w", err)
	}
	defer tok.Close()
	var env *uint16
	if err := windows.CreateEnvironmentBlock(&env, tok, false); err == nil {
		defer windows.DestroyEnvironmentBlock(env)
	}
	app, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return nil, err
	}
	cl, err := windows.UTF16PtrFromString(cmdline)
	if err != nil {
		return nil, err
	}
	desktop, _ := windows.UTF16PtrFromString(`winsta0\default`)
	si := windows.StartupInfo{Desktop: desktop}
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation
	const createUnicodeEnvironment, createNoWindow, createSuspended = 0x00000400, 0x08000000, 0x00000004
	flags := uint32(createUnicodeEnvironment)
	if o.NoWindow {
		flags |= createNoWindow
	}
	if o.KillOnClose {
		flags |= createSuspended
	}
	if err := windows.CreateProcessAsUser(tok, app, cl, nil, nil, false, flags, env, nil, &si, &pi); err != nil {
		return nil, fmt.Errorf("CreateProcessAsUser: %w", err)
	}
	defer windows.CloseHandle(pi.Thread)
	p := &Process{Handle: pi.Process, PID: pi.ProcessId}
	if o.KillOnClose {
		job, err := killOnCloseJob()
		if err == nil {
			err = windows.AssignProcessToJobObject(job, pi.Process)
		}
		if err != nil {
			if job != 0 {
				_ = windows.CloseHandle(job)
			}
			_ = p.Close()
			return nil, fmt.Errorf("job object: %w", err)
		}
		p.job = job
		if _, err := windows.ResumeThread(pi.Thread); err != nil {
			_ = p.Close()
			return nil, fmt.Errorf("ResumeThread: %w", err)
		}
	}
	return p, nil
}

func killOnCloseJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		_ = windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}

// IsLocalSystem reports whether this process runs as LocalSystem (the service).
func IsLocalSystem() bool {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false
	}
	return tu.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
}
