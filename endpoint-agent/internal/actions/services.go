package actions

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
)

// ServiceControl is the OS service manager (Windows: the SCM).
type ServiceControl interface {
	// List returns every Win32 service (name, display name, status, start type).
	List() ([]model.Service, error)
	// Query returns one service by name (case-insensitive) or ErrNotFound.
	Query(name string) (model.Service, error)
	Start(name string) error
	Stop(name string) error
	// SetStartType changes only the startup type (auto | auto_delayed | manual | disabled).
	SetStartType(name, startType string) error
}

// Service actions.
const (
	ServiceStop    = "stop"
	ServiceStart   = "start"
	ServiceDisable = "disable"
	ServiceRestore = "restore"
)

// AgentServiceName is this agent's own Windows service (internal/service).
const AgentServiceName = "CNAPPAgent"

// ProtectedServices may never be stopped or disabled from the console:
// this agent, and the services Windows needs to boot, sign users in, stay
// manageable (RPC / WMI / Group Policy / event log) and stay protected
// (Defender, firewall, crypto). TermService is also protected while an
// attended remote session runs. Mirrored server-side in
// backend/app/services/endpoint_actions.py (PROTECTED_SERVICES) and listed in
// docs/DEVICE_MANAGEMENT.md#endpoint-actions.
var ProtectedServices = []string{
	AgentServiceName,
	// core OS, RPC / COM, sessions, Plug and Play, power
	"RpcSs", "RpcEptMapper", "DcomLaunch", "LSM", "SamSs", "PlugPlay", "Power", "BrokerInfrastructure",
	"SystemEventsBroker", "CoreMessagingRegistrar", "ProfSvc", "UserManager", "gpsvc", "Netlogon",
	// management and logging
	"EventLog", "Winmgmt", "Schedule",
	// networking the agent needs to reach the server
	"Dhcp", "Dnscache", "nsi",
	// security
	"WinDefend", "WdNisSvc", "Sense", "SecurityHealthService", "wscsvc", "mpssvc", "BFE", "CryptSvc", "KeyIso",
}

// RemoteSessionService is protected while an attended remote session is active.
const RemoteSessionService = "TermService"

// IsProtected reports whether a service may not be stopped or disabled.
func IsProtected(name string, remoteActive bool) bool {
	if remoteActive && sameFold(name, RemoteSessionService) {
		return true
	}
	return slices.ContainsFunc(ProtectedServices, func(p string) bool { return sameFold(p, name) })
}

// restorableStartTypes are the startup types restore_to may name.
var restorableStartTypes = []string{"auto", "auto_delayed", "manual"}

// ServiceParams of a manage_service command.
type ServiceParams struct {
	Service   string
	Action    string
	RestoreTo string // restore only, optional: the server's record of the previous startup type
}

// ParseServiceParams validates manage_service parameters.
func ParseServiceParams(p map[string]any) (ServiceParams, error) {
	var out ServiceParams
	name, ok := str(p, "service")
	if !ok || !serviceNameRe.MatchString(name) {
		return out, errors.New("service must be a Windows service name (1-256 letters, digits, spaces and _ . $ @ { } ~ + -)")
	}
	action, _ := str(p, "action")
	if !slices.Contains([]string{ServiceStop, ServiceStart, ServiceDisable, ServiceRestore}, action) {
		return out, errors.New("action must be stop, start, disable or restore")
	}
	out.Service, out.Action = name, action
	if v, present := p["restore_to"]; present && v != nil {
		r, ok := v.(string)
		if !ok || action != ServiceRestore || !slices.Contains(restorableStartTypes, r) {
			return out, errors.New("restore_to is only allowed with action restore and must be auto, auto_delayed or manual")
		}
		out.RestoreTo = r
	}
	return out, nil
}

func (m *Manager) remoteActive() bool { return m.RemoteActive != nil && m.RemoteActive() }

func (m *Manager) manageService(ctx context.Context, commandID string, p ServiceParams) Result {
	svc, err := m.Services.Query(p.Service)
	if errors.Is(err, ErrNotFound) {
		return failed("service %q does not exist on this device", p.Service)
	}
	if err != nil {
		return failed("querying service %s: %v", p.Service, err)
	}
	name := svc.Name
	if (p.Action == ServiceStop || p.Action == ServiceDisable) && IsProtected(name, m.remoteActive()) {
		why := "it is a protected system or security service"
		if sameFold(name, AgentServiceName) {
			why = "it is this agent's own service"
		} else if sameFold(name, RemoteSessionService) {
			why = "an attended remote session is active"
		}
		return Result{Status: "rejected", Output: fmt.Sprintf("refused to %s %s: %s", p.Action, name, why),
			Data: map[string]any{"service": name, "action": p.Action, "error_code": "ERR_PROTECTED_SERVICE"}}
	}
	var r Result
	switch p.Action {
	case ServiceStop:
		r = m.stopService(ctx, svc)
	case ServiceStart:
		r = m.startService(ctx, svc)
	case ServiceDisable:
		r = m.disableService(svc, commandID)
	case ServiceRestore:
		r = m.restoreService(svc, p.RestoreTo)
	}
	if r.Data == nil {
		r.Data = map[string]any{}
	}
	r.Data["service"], r.Data["action"] = name, p.Action
	if now, err := m.Services.Query(name); err == nil {
		r.Data["status"], r.Data["start_type"] = now.Status, now.StartType
	}
	return r
}

func (m *Manager) stopService(ctx context.Context, svc model.Service) Result {
	if svc.Status == "stopped" {
		return Result{Status: "succeeded", Output: fmt.Sprintf("%s is already stopped", svc.Name)}
	}
	if err := m.Services.Stop(svc.Name); err != nil {
		return failed("stopping %s: %v", svc.Name, err)
	}
	if !m.waitStatus(ctx, svc.Name, "stopped") {
		return failed("%s did not stop within %s", svc.Name, m.ServiceWait)
	}
	return Result{Status: "succeeded", Output: fmt.Sprintf("%s stopped (startup type unchanged: %s)", svc.Name, svc.StartType)}
}

func (m *Manager) startService(ctx context.Context, svc model.Service) Result {
	if svc.StartType == "disabled" {
		return failed("%s is disabled: restore its startup type before starting it", svc.Name)
	}
	if svc.Status == "running" {
		return Result{Status: "succeeded", Output: fmt.Sprintf("%s is already running", svc.Name)}
	}
	if err := m.Services.Start(svc.Name); err != nil {
		return failed("starting %s: %v", svc.Name, err)
	}
	if !m.waitStatus(ctx, svc.Name, "running") {
		return failed("%s did not reach the running state within %s", svc.Name, m.ServiceWait)
	}
	return Result{Status: "succeeded", Output: fmt.Sprintf("%s started", svc.Name)}
}

func (m *Manager) waitStatus(ctx context.Context, name, want string) bool {
	return m.wait(ctx, m.ServiceWait, func() bool {
		s, err := m.Services.Query(name)
		return err == nil && s.Status == want
	})
}

// disableService saves the current startup type (persisted before the change)
// and sets Disabled. A service that is already disabled keeps the startup type
// saved by an earlier disable, so restore still returns to the original.
func (m *Manager) disableService(svc model.Service, commandID string) Result {
	st, err := m.load()
	if err != nil {
		return failed("reading saved startup types: %v", err)
	}
	key := strings.ToLower(svc.Name)
	prev, have := st.Services[key]
	if svc.StartType == "disabled" {
		if have {
			return Result{Status: "succeeded", Output: fmt.Sprintf("%s is already disabled (restore returns it to %s)",
				svc.Name, prev.StartType), Data: map[string]any{"previous_start_type": prev.StartType}}
		}
		return Result{Status: "succeeded", Output: fmt.Sprintf("%s was already disabled before this action; there is no other startup type to restore", svc.Name),
			Data: map[string]any{"previous_start_type": "disabled"}}
	}
	if !have {
		if st.Services == nil {
			st.Services = map[string]savedService{}
		}
		st.Services[key] = savedService{Name: svc.Name, StartType: svc.StartType, SavedAt: time.Now().UTC(), CommandID: commandID}
		if err := m.store(st); err != nil {
			return failed("could not save the current startup type, nothing was changed: %v", err)
		}
		prev = st.Services[key]
	}
	if err := m.Services.SetStartType(svc.Name, "disabled"); err != nil {
		if !have { // nothing changed: forget the saved value again
			delete(st.Services, key)
			_ = m.store(st)
		}
		return failed("setting %s to Disabled: %v", svc.Name, err)
	}
	out := fmt.Sprintf("%s startup type set to Disabled (was %s); it keeps its current state (%s) until it is stopped or the device restarts",
		svc.Name, prev.StartType, svc.Status)
	return Result{Status: "succeeded", Output: out, Data: map[string]any{"previous_start_type": prev.StartType}}
}

// restoreService puts back the startup type saved by disable (or, when this
// agent has no record, the one the server recorded with the disable result).
func (m *Manager) restoreService(svc model.Service, restoreTo string) Result {
	st, err := m.load()
	if err != nil {
		return failed("reading saved startup types: %v", err)
	}
	key := strings.ToLower(svc.Name)
	target, from := restoreTo, "the server's record"
	if s, ok := st.Services[key]; ok {
		target, from = s.StartType, "the value saved on this device"
	}
	if target == "" {
		return failed("there is no saved startup type for %s (it was not disabled by this agent); change it with a script instead", svc.Name)
	}
	if err := m.Services.SetStartType(svc.Name, target); err != nil {
		return failed("restoring the startup type of %s to %s: %v", svc.Name, target, err)
	}
	delete(st.Services, key)
	if err := m.store(st); err != nil {
		return failed("startup type restored to %s, but the saved value could not be cleared: %v", target, err)
	}
	return Result{Status: "succeeded", Output: fmt.Sprintf("%s startup type restored to %s (from %s); the service was not started",
		svc.Name, target, from), Data: map[string]any{"previous_start_type": svc.StartType, "restored_start_type": target}}
}

// ListServices is the services inventory sent with check-ins (nil when unsupported).
func (m *Manager) ListServices() ([]model.Service, error) {
	if !supportedOS || m.Services == nil {
		return nil, nil
	}
	list, err := m.Services.List()
	if len(list) > MaxServices {
		list = list[:MaxServices]
	}
	return list, err
}

// MaxServices caps the inventory (also enforced server-side).
const MaxServices = 2000
