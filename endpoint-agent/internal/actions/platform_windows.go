//go:build windows

package actions

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
)

const platformSupported = true

func platformBackends() (ServiceControl, Registry, Programs) {
	return scm{}, hklm{}, winPrograms{}
}

// ----------------------------------------------------------------------------- services (SCM)

type scm struct{}

func connect() (*mgr.Mgr, error) {
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil, fmt.Errorf("opening the service control manager: %w", err)
	}
	return &mgr.Mgr{Handle: h}, nil
}

// open opens a service with only the rights an action needs (some protected
// services refuse SERVICE_ALL_ACCESS even to LocalSystem).
func open(m *mgr.Mgr, name string, access uint32) (*mgr.Service, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	h, err := windows.OpenService(m.Handle, p, access)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &mgr.Service{Name: name, Handle: h}, nil
}

func statusName(s svc.State) string {
	switch s {
	case svc.Running:
		return "running"
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "start_pending"
	case svc.StopPending:
		return "stop_pending"
	case svc.Paused:
		return "paused"
	}
	return "other"
}

func startTypeName(t uint32, delayed bool) string {
	switch t {
	case windows.SERVICE_BOOT_START:
		return "boot"
	case windows.SERVICE_SYSTEM_START:
		return "system"
	case windows.SERVICE_AUTO_START:
		if delayed {
			return "auto_delayed"
		}
		return "auto"
	case windows.SERVICE_DEMAND_START:
		return "manual"
	case windows.SERVICE_DISABLED:
		return "disabled"
	}
	return "other"
}

func describe(m *mgr.Mgr, name string) (model.Service, error) {
	s, err := open(m, name, windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return model.Service{}, err
	}
	defer s.Close()
	cfg, err := s.Config()
	if err != nil {
		return model.Service{}, err
	}
	st, err := s.Query()
	if err != nil {
		return model.Service{}, err
	}
	return model.Service{Name: name, DisplayName: cfg.DisplayName, Status: statusName(st.State),
		StartType: startTypeName(cfg.StartType, cfg.DelayedAutoStart)}, nil
}

func (scm) List() ([]model.Service, error) {
	m, err := connect()
	if err != nil {
		return nil, err
	}
	defer m.Disconnect()
	names, err := m.ListServices() // Win32 services only (no drivers)
	if err != nil {
		return nil, err
	}
	out := make([]model.Service, 0, len(names))
	for _, n := range names {
		if s, err := describe(m, n); err == nil {
			out = append(out, s)
		}
	}
	return out, nil
}

// canonical returns the service's registered name (OpenService is
// case-insensitive; protected-list checks and saved values use this name).
func canonical(m *mgr.Mgr, name string) (string, error) {
	names, err := m.ListServices()
	if err != nil {
		return "", err
	}
	for _, n := range names {
		if strings.EqualFold(n, name) {
			return n, nil
		}
	}
	return "", ErrNotFound
}

func (scm) Query(name string) (model.Service, error) {
	m, err := connect()
	if err != nil {
		return model.Service{}, err
	}
	defer m.Disconnect()
	n, err := canonical(m, name)
	if err != nil {
		return model.Service{}, err
	}
	return describe(m, n)
}

func (scm) Start(name string) error {
	m, err := connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := open(m, name, windows.SERVICE_START|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Start()
}

func (scm) Stop(name string) error {
	m, err := connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := open(m, name, windows.SERVICE_STOP|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return err
	}
	defer s.Close()
	if _, err := s.Control(svc.Stop); err != nil {
		if errors.Is(err, windows.ERROR_DEPENDENT_SERVICES_RUNNING) {
			return errors.New("other running services depend on it; stop those first")
		}
		return err
	}
	return nil
}

// SetStartType changes only dwStartType (and the delayed-start flag) with
// ChangeServiceConfig/SERVICE_NO_CHANGE: mgr.Service.UpdateConfig would also
// rewrite the account and an empty password.
func (scm) SetStartType(name, startType string) error {
	var t uint32
	delayed := false
	switch startType {
	case "auto":
		t = windows.SERVICE_AUTO_START
	case "auto_delayed":
		t, delayed = windows.SERVICE_AUTO_START, true
	case "manual":
		t = windows.SERVICE_DEMAND_START
	case "disabled":
		t = windows.SERVICE_DISABLED
	default:
		return fmt.Errorf("unsupported startup type %q", startType)
	}
	m, err := connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := open(m, name, windows.SERVICE_CHANGE_CONFIG|windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := windows.ChangeServiceConfig(s.Handle, windows.SERVICE_NO_CHANGE, t, windows.SERVICE_NO_CHANGE,
		nil, nil, nil, nil, nil, nil, nil); err != nil {
		return err
	}
	if t == windows.SERVICE_AUTO_START || t == windows.SERVICE_DEMAND_START {
		info := windows.SERVICE_DELAYED_AUTO_START_INFO{}
		if delayed {
			info.IsDelayedAutoStartUp = 1
		}
		if err := windows.ChangeServiceConfig2(s.Handle, windows.SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
			(*byte)(unsafe.Pointer(&info))); err != nil && t == windows.SERVICE_AUTO_START {
			return fmt.Errorf("setting delayed start: %w", err)
		}
	}
	return nil
}

// ----------------------------------------------------------------------------- registry (HKLM, 64-bit view)

type hklm struct{}

const view = registry.WOW64_64KEY

func (hklm) GetDWORD(key, name string) (uint32, bool, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.QUERY_VALUE|view)
	if errors.Is(err, registry.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	defer k.Close()
	v, typ, err := k.GetIntegerValue(name)
	if errors.Is(err, registry.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if typ != registry.DWORD {
		return 0, false, fmt.Errorf("%s\\%s is not a REG_DWORD", key, name)
	}
	return uint32(v), true, nil
}

func (hklm) SetDWORD(key, name string, value uint32) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, key, registry.SET_VALUE|view)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetDWordValue(name, value)
}

func (hklm) DeleteValue(key, name string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.SET_VALUE|view)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.DeleteValue(name); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return nil
}

func (hklm) KeyExists(key string) (bool, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.QUERY_VALUE|view)
	if errors.Is(err, registry.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	k.Close()
	return true, nil
}

func (hklm) DeleteKeyIfEmpty(key string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS|view)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	info, err := k.Stat()
	k.Close()
	if err != nil {
		return err
	}
	if info.SubKeyCount > 0 || info.ValueCount > 0 {
		return nil
	}
	return registry.DeleteKey(registry.LOCAL_MACHINE, key)
}

// ----------------------------------------------------------------------------- programs

type winPrograms struct{}

const uninstallPath = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`

func (winPrograms) Lookup(source, key string) (Program, error) {
	access := uint32(registry.WOW64_64KEY)
	if source == "registry_hklm32" {
		access = registry.WOW64_32KEY
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, uninstallPath+`\`+key, registry.QUERY_VALUE|access)
	if errors.Is(err, registry.ErrNotExist) {
		return Program{}, ErrNotFound
	}
	if err != nil {
		return Program{}, err
	}
	defer k.Close()
	p := Program{Key: key, Source: source}
	p.DisplayName, _, _ = k.GetStringValue("DisplayName")
	p.DisplayVersion, _, _ = k.GetStringValue("DisplayVersion")
	p.Publisher, _, _ = k.GetStringValue("Publisher")
	p.InstallLocation, _, _ = k.GetStringValue("InstallLocation")
	p.UninstallString, _, _ = k.GetStringValue("UninstallString")
	p.QuietUninstallString, _, _ = k.GetStringValue("QuietUninstallString")
	if v, _, err := k.GetIntegerValue("WindowsInstaller"); err == nil && v == 1 {
		p.WindowsInstaller = true
	}
	return p, nil
}

type capped struct{ b []byte }

func (c *capped) Write(p []byte) (int, error) {
	if room := 4096 - len(c.b); room > 0 {
		c.b = append(c.b, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

func (winPrograms) Run(ctx context.Context, c Cmd) (int, string, error) {
	cmd := exec.CommandContext(ctx, c.Path, c.Args...)
	attr := &syscall.SysProcAttr{HideWindow: true}
	if c.CmdLine != "" {
		attr.CmdLine = c.CmdLine // verbatim QuietUninstallString, no shell
	}
	cmd.SysProcAttr = attr
	var out capped
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) && ctx.Err() == nil {
		return ee.ExitCode(), string(out.b), nil
	}
	if err != nil {
		return -1, string(out.b), err
	}
	return 0, string(out.b), nil
}
