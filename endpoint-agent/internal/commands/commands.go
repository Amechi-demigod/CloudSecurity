// Package commands executes remote actions from a strict allowlist.
//
// The agent has NO generic "run this command/script" capability. Whatever the
// server sends, only the action types below are executed, with validated
// parameters, each at most once, and only before it expires. run_script only
// runs scripts from a bundle signed by a script-signing key compiled into the
// agent, with parameters validated against the signed schema (internal/scripts);
// wipe_device only works on Windows devices that opted in at install time
// (internal/wipe); start_remote_session never captures anything before the
// signed-in user allows it (internal/remote).
package commands

import (
	"context"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/remote"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/scripts"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/wipe"
)

// Allowed command types.
const (
	LockDevice            = "lock_device"
	RecheckPosture        = "recheck_posture"
	CollectLogs           = "collect_logs"
	RestartAgent          = "restart_agent"
	UpdateCheckInInterval = "update_check_in_interval"
	EnableLostMode        = "enable_lost_mode"
	DisableLostMode       = "disable_lost_mode"
	WipeDevice            = "wipe_device"
	RunScript             = "run_script"
	// CheckForUpdate makes the agent check in now and start an offered update
	// without the random delay. It cannot name a release or a binary: the
	// offer still comes from the check-in and the agent verifies the signed
	// manifest, hashes and version policy exactly as for a scheduled update.
	CheckForUpdate = "check_for_update"
	// IsolateHost / RestoreHost are "Suspend sign-in" / "Restore sign-in"
	// (internal names kept for API compatibility with the backend, which
	// shipped them first) - see internal/signin.
	IsolateHost = "isolate_host"
	RestoreHost = "restore_host"
	// StartRemoteSession opens an attended remote session (internal/remote):
	// nothing is captured until the signed-in user allows it.
	StartRemoteSession = remote.CommandType
)

// Lost-mode message limits (also enforced server-side).
const MaxLostMessage = 300

var phoneRe = regexp.MustCompile(`^[0-9+][0-9 ()./+-]{2,31}$`)

// Interval bounds (also enforced server-side).
const (
	MinIntervalSeconds = 300
	MaxIntervalSeconds = 86400
)

// allowedParams lists the only parameters each command may carry.
var allowedParams = map[string][]string{
	LockDevice:            {},
	RecheckPosture:        {},
	CollectLogs:           {},
	RestartAgent:          {},
	UpdateCheckInInterval: {"interval_seconds"},
	EnableLostMode:        {"message", "phone"},
	DisableLostMode:       {},
	WipeDevice:            {"mode", "hostname"},
	RunScript:             {"bundle_id", "bundle_version", "script", "script_sha256", "parameters"},
	CheckForUpdate:        {},
	IsolateHost:           {"incident_id"},
	RestoreHost:           {},
	StartRemoteSession:    remote.AllowedParams,
}

// incidentIDRe matches an optional, operator-supplied incident reference
// shown on the suspend-sign-in banner.
var incidentIDRe = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)

// IncidentIDParam extracts and validates isolate_host's optional incident_id.
// Empty/absent is allowed (the command id is used as the reference instead).
func IncidentIDParam(p map[string]any) (string, error) {
	raw, ok := p["incident_id"]
	if !ok || raw == nil {
		return "", nil
	}
	s, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("incident_id must be a string")
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if !incidentIDRe.MatchString(s) {
		return "", fmt.Errorf("incident_id must be 1-64 characters: letters, digits, '.', '_', ':', '-' only")
	}
	return s, nil
}

// Allowed reports whether a command type is in the allowlist.
func Allowed(t string) bool {
	_, ok := allowedParams[t]
	return ok
}

// ErrRejected marks commands refused by local validation.
var ErrRejected = errors.New("rejected")

// Validate checks a delivered command against the allowlist, the device
// binding and the expiry. `now` should be server-time adjusted.
func Validate(c model.Command, deviceID string, now time.Time) error {
	if !Allowed(c.Type) {
		return fmt.Errorf("%w: command type %q is not in the agent allowlist", ErrRejected, c.Type)
	}
	if c.DeviceID != deviceID {
		return fmt.Errorf("%w: command is bound to another device", ErrRejected)
	}
	if c.ID == "" || len(c.Nonce) < 16 {
		return fmt.Errorf("%w: command id/nonce missing", ErrRejected)
	}
	if !c.ExpiresAt.IsZero() && now.After(c.ExpiresAt) {
		return fmt.Errorf("%w: command expired at %s", ErrRejected, c.ExpiresAt.Format(time.RFC3339))
	}
	allowed := allowedParams[c.Type]
	for k := range c.Params {
		ok := false
		for _, a := range allowed {
			ok = ok || a == k
		}
		if !ok {
			return fmt.Errorf("%w: unexpected parameter %q for %s", ErrRejected, k, c.Type)
		}
	}
	var err error
	switch c.Type {
	case UpdateCheckInInterval:
		_, err = IntervalParam(c.Params)
	case EnableLostMode:
		_, _, err = LostModeParams(c.Params)
	case WipeDevice:
		err = wipe.ValidateParams(c)
	case RunScript:
		err = scripts.ValidateCommand(c)
	case IsolateHost:
		_, err = IncidentIDParam(c.Params)
	case StartRemoteSession:
		_, err = remote.ParseParams(c.Params)
	}
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRejected, err)
	}
	return nil
}

// LostModeParams extracts and validates the lost-mode message and phone.
func LostModeParams(p map[string]any) (string, string, error) {
	msg, ok1 := p["message"].(string)
	phone, ok2 := p["phone"].(string)
	if !ok1 || !ok2 {
		return "", "", fmt.Errorf("message and phone are required")
	}
	msg = strings.TrimSpace(msg)
	if n := utf8.RuneCountInString(msg); n == 0 || n > MaxLostMessage || strings.Count(msg, "\n") > 5 {
		return "", "", fmt.Errorf("message must be 1-%d characters and at most 6 lines", MaxLostMessage)
	}
	for _, r := range msg {
		if (r < 0x20 && r != '\n') || r == 0x7f {
			return "", "", fmt.Errorf("message must not contain control characters")
		}
	}
	if phone = strings.TrimSpace(phone); !phoneRe.MatchString(phone) {
		return "", "", fmt.Errorf("phone must be 3-32 characters: digits, spaces and + ( ) . / -")
	}
	return msg, phone, nil
}

// IntervalParam extracts and validates interval_seconds.
func IntervalParam(p map[string]any) (int, error) {
	f, ok := p["interval_seconds"].(float64)
	if !ok || f != math.Trunc(f) || f < MinIntervalSeconds || f > MaxIntervalSeconds {
		return 0, fmt.Errorf("interval_seconds must be an integer between %d and %d", MinIntervalSeconds, MaxIntervalSeconds)
	}
	return int(f), nil
}

// Deps are the agent capabilities the handlers use.
type Deps struct {
	CheckIn     func(ctx context.Context) error
	BuildLogs   func(ctx context.Context) ([]byte, error)
	UploadLogs  func(ctx context.Context, c model.Command, gz []byte) error
	SetInterval func(seconds int) error
	Lock        func(ctx context.Context) (string, error)
	LostMode    func(ctx context.Context, enable bool, message, phone string) (string, error)
	Wipe        func(ctx context.Context, c model.Command) Outcome
	RunScript   func(ctx context.Context, c model.Command) Outcome
	// CheckForUpdate checks in immediately and schedules an offered update
	// without jitter; it returns a human-readable outcome.
	CheckForUpdate func(ctx context.Context) (string, error)
	// IsolateHost / RestoreHost: "Suspend sign-in" / "Restore sign-in". These
	// need the full Outcome shape (incl. "rejected" for the pre-flight-blocked
	// case), like Wipe/RunScript, not the simpler (string, error) shape
	// LostMode/Lock use.
	IsolateHost func(ctx context.Context, c model.Command) Outcome
	RestoreHost func(ctx context.Context, c model.Command) Outcome
	// RemoteSession returns once the session is connected (it then runs in
	// the background) or could not start; ResultData carries the error_code.
	RemoteSession func(ctx context.Context, c model.Command) Outcome
}

// Outcome of an executed command. After (if set) runs once the result has been
// reported, e.g. to restart the agent.
type Outcome struct {
	Status   string // succeeded | failed | rejected
	Output   string
	After    func()
	ExitCode *int // run_script
	// ResultData is isolate_host/restore_host/start_remote_session only:
	// pre-flight findings, crash-recovery outcomes or the remote-session
	// error_code, sent as result_data on the result POST and strictly
	// validated server-side against schemas_devices.RESULT_DATA_SCHEMAS.
	// Left nil/empty for every other command type - never POSTed then.
	ResultData map[string]any
}

// Execute runs an already validated command.
func Execute(ctx context.Context, c model.Command, d Deps, restart func()) Outcome {
	switch c.Type {
	case RecheckPosture:
		if err := d.CheckIn(ctx); err != nil {
			return Outcome{Status: "failed", Output: "check-in failed: " + err.Error()}
		}
		return Outcome{Status: "succeeded", Output: "full inventory and posture check-in completed"}
	case CollectLogs:
		gz, err := d.BuildLogs(ctx)
		if err != nil {
			return Outcome{Status: "failed", Output: "building log bundle: " + err.Error()}
		}
		if err := d.UploadLogs(ctx, c, gz); err != nil {
			return Outcome{Status: "failed", Output: "uploading log bundle: " + err.Error()}
		}
		return Outcome{Status: "succeeded", Output: fmt.Sprintf("uploaded log bundle (%d bytes)", len(gz))}
	case UpdateCheckInInterval:
		n, _ := IntervalParam(c.Params)
		if err := d.SetInterval(n); err != nil {
			return Outcome{Status: "failed", Output: err.Error()}
		}
		return Outcome{Status: "succeeded", Output: fmt.Sprintf("check-in interval set to %d seconds", n)}
	case CheckForUpdate:
		if d.CheckForUpdate == nil {
			return Outcome{Status: "failed", Output: "self-update is not available in this agent mode"}
		}
		out, err := d.CheckForUpdate(ctx)
		if err != nil {
			return Outcome{Status: "failed", Output: err.Error()}
		}
		return Outcome{Status: "succeeded", Output: out}
	case RestartAgent:
		return Outcome{Status: "succeeded", Output: "agent restarting", After: restart}
	case LockDevice:
		out, err := d.Lock(ctx)
		if err != nil {
			if out != "" {
				out += "\n"
			}
			return Outcome{Status: "failed", Output: out + err.Error()}
		}
		return Outcome{Status: "succeeded", Output: out}
	case EnableLostMode, DisableLostMode:
		if d.LostMode == nil {
			return Outcome{Status: "rejected", Output: "lost mode is not available"}
		}
		msg, phone, _ := LostModeParams(c.Params)
		out, err := d.LostMode(ctx, c.Type == EnableLostMode, msg, phone)
		if err != nil {
			status := "failed"
			if errors.Is(err, ErrRejected) {
				status = "rejected"
			}
			return Outcome{Status: status, Output: strings.TrimSpace(out + "\n" + err.Error())}
		}
		return Outcome{Status: "succeeded", Output: out}
	case WipeDevice:
		if d.Wipe == nil {
			return Outcome{Status: "rejected", Output: "remote wipe is not available"}
		}
		return d.Wipe(ctx, c)
	case RunScript:
		if d.RunScript == nil {
			return Outcome{Status: "rejected", Output: "scripts are not available"}
		}
		return d.RunScript(ctx, c)
	case IsolateHost:
		if d.IsolateHost == nil {
			return Outcome{Status: "rejected", Output: "suspend sign-in is not available"}
		}
		return d.IsolateHost(ctx, c)
	case RestoreHost:
		if d.RestoreHost == nil {
			return Outcome{Status: "rejected", Output: "restore sign-in is not available"}
		}
		return d.RestoreHost(ctx, c)
	case StartRemoteSession:
		if d.RemoteSession == nil {
			return Outcome{Status: "failed", Output: "remote sessions are not available in this agent mode",
				ResultData: map[string]any{"error_code": remote.ErrHelper}}
		}
		return d.RemoteSession(ctx, c)
	}
	return Outcome{Status: "rejected", Output: "command type not in allowlist"}
}
