// Package commands executes remote actions from a strict allowlist.
//
// The agent has NO generic "run this command/script" capability. Whatever the
// server sends, only the handful of action types below are executed, with
// validated parameters, each at most once, and only before it expires.
package commands

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
)

// Allowed command types.
const (
	LockDevice            = "lock_device"
	RecheckPosture        = "recheck_posture"
	CollectLogs           = "collect_logs"
	RestartAgent          = "restart_agent"
	UpdateCheckInInterval = "update_check_in_interval"
)

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
	if c.Type == UpdateCheckInInterval {
		if _, err := IntervalParam(c.Params); err != nil {
			return fmt.Errorf("%w: %v", ErrRejected, err)
		}
	}
	return nil
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
}

// Outcome of an executed command. After (if set) runs once the result has been
// reported, e.g. to restart the agent.
type Outcome struct {
	Status string // succeeded | failed | rejected
	Output string
	After  func()
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
	}
	return Outcome{Status: "rejected", Output: "command type not in allowlist"}
}
