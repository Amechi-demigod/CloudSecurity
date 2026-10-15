//go:build windows

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// BinaryPath is where Install places the agent.
func BinaryPath() string {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	return filepath.Join(pf, "CNAPP Agent", "cnapp-agent.exe")
}

// IsService reports whether the Service Control Manager started this process.
func IsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

type handler struct{ run func(ctx context.Context) error }

func (h handler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.run(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			cancel()
			if err != nil {
				return true, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(20 * time.Second):
				}
				return false, 0
			}
		}
	}
}

// RunService runs fn under the Service Control Manager until stopped.
func RunService(fn func(ctx context.Context) error) error {
	return svc.Run(WindowsServiceName, handler{run: fn})
}

func isAdmin() bool {
	var sid *windows.SID
	if err := windows.AllocateAndInitializeSid(&windows.SECURITY_NT_AUTHORITY, 2, windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &sid); err != nil {
		return false
	}
	defer windows.FreeSid(sid)
	ok, err := windows.Token(0).IsMember(sid)
	return err == nil && ok
}

func stopAndWait(s *mgr.Service) {
	st, err := s.Query()
	if err != nil || st.State == svc.Stopped {
		return
	}
	_, _ = s.Control(svc.Stop)
	for i := 0; i < 40; i++ {
		if st, err := s.Query(); err != nil || st.State == svc.Stopped {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// Install copies the binary to Program Files and registers an auto-start
// service running as LocalSystem, restarted automatically on failure.
func Install(o Options) error {
	if !isAdmin() {
		return errors.New("install must run from an elevated (Administrator) prompt")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connecting to the service manager: %w", err)
	}
	defer m.Disconnect()
	if s, err := m.OpenService(WindowsServiceName); err == nil { // upgrade in place
		stopAndWait(s)
		_ = s.Delete()
		s.Close()
		time.Sleep(time.Second)
	}
	dst := BinaryPath()
	if err := copyFile(exe, dst, 0o755); err != nil {
		return err
	}
	s, err := m.CreateService(WindowsServiceName, dst, mgr.Config{
		DisplayName: DisplayName, Description: Description, StartType: mgr.StartAutomatic,
		DelayedAutoStart: true, ErrorControl: mgr.ErrorNormal,
	}, serviceArgs(o)...)
	if err != nil {
		return fmt.Errorf("creating service: %w", err)
	}
	defer s.Close()
	// restart_agent exits non-zero; the SCM then restarts the service.
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 2 * time.Minute},
	}, 86400); err != nil {
		return fmt.Errorf("setting recovery actions: %w", err)
	}
	_ = s.SetRecoveryActionsOnNonCrashFailures(true)
	return s.Start()
}

// Uninstall stops and deletes the service and removes the installed binary.
func Uninstall() error {
	if !isAdmin() {
		return errors.New("uninstall must run from an elevated (Administrator) prompt")
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if s, err := m.OpenService(WindowsServiceName); err == nil {
		stopAndWait(s)
		if err := s.Delete(); err != nil {
			s.Close()
			return err
		}
		s.Close()
	}
	exe, _ := os.Executable()
	dst := BinaryPath()
	if !same(exe, dst) {
		_ = os.Remove(dst)
		_ = os.Remove(filepath.Dir(dst))
	}
	return nil
}
