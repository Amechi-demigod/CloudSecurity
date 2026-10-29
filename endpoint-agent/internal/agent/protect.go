package agent

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/commands"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/lostmode"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/scripts"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/signin"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/state"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/wipe"
)

// addAgentPosture adds the agent's own state to a report: lost mode and the
// remote-wipe readiness (both "info" checks: they never raise posture issues).
func (a *Agent) addAgentPosture(ctx context.Context, r *model.Report) {
	if r.Device.Hostname != "" {
		a.mu.Lock()
		a.hostname = r.Device.Hostname
		a.mu.Unlock()
	}
	if r.Posture == nil {
		r.Posture = map[string]model.PostureCheck{}
	}
	if a.LostMode != nil {
		st := a.LostMode.Status()
		detail := "lost mode off"
		if st["active"] == true {
			detail = "lost mode active since " + st["since"].(string)
		}
		r.Posture["lost_mode"] = model.Check(model.StatusInfo, detail, st)
	}
	rd := a.wipeReadiness(ctx)
	r.Posture["remote_wipe"] = model.Check(model.StatusInfo, rd.Detail, rd.Data())
	if a.Signin != nil {
		st := a.Signin.Status()
		detail := "sign-in not suspended"
		if st["active"] == true {
			detail = "sign-in suspended"
		}
		r.Posture["isolation"] = model.Check(model.StatusInfo, detail, st)
	}
}

func (a *Agent) wipeOptIn() (bool, error) {
	pol, err := state.LoadPolicy(a.Paths)
	return pol.AllowWipe, err
}

func (a *Agent) wipeReadiness(ctx context.Context) wipe.Readiness {
	opt, err := a.wipeOptIn()
	a.mu.Lock()
	cached, at := a.probe, a.probedAt
	a.mu.Unlock()
	if cached != nil && time.Since(at) < wipeProbeTTL && cached.OptIn == opt {
		return *cached
	}
	var rd wipe.Readiness
	if a.WipeProbe != nil {
		rd = a.WipeProbe(ctx, opt)
	}
	if err != nil {
		rd.Error = strings.TrimSpace(rd.Error + " policy: " + err.Error())
	}
	a.mu.Lock()
	a.probe, a.probedAt = &rd, time.Now()
	a.mu.Unlock()
	return rd
}

func (a *Agent) currentHostname() string {
	a.mu.Lock()
	h := a.hostname
	a.mu.Unlock()
	if h == "" {
		h, _ = os.Hostname()
	}
	return h
}

func (a *Agent) lostMode(ctx context.Context, enable bool, message, phone string) (string, error) {
	if a.LostMode == nil {
		return "", errLostModeUnavailable
	}
	if enable {
		out, err := a.LostMode.Enable(ctx, message, phone)
		a.mu.Lock()
		a.nextRelock = time.Now().Add(lostmode.RelockInterval)
		a.mu.Unlock()
		return out, err
	}
	return a.LostMode.Disable(ctx)
}

// maybeRelock locks active sessions again while lost mode lasts.
func (a *Agent) maybeRelock(ctx context.Context) {
	if a.LostMode == nil {
		return
	}
	a.mu.Lock()
	due := !time.Now().Before(a.nextRelock)
	if due {
		a.nextRelock = time.Now().Add(lostmode.RelockInterval)
	}
	a.mu.Unlock()
	if !due {
		return
	}
	if active, out := a.LostMode.Relock(ctx); active {
		slog.Info("lost mode active: sessions locked again", "result", out)
	}
}

func (a *Agent) wipe(ctx context.Context, c model.Command) commands.Outcome {
	o := wipe.Run(ctx, c, wipe.Deps{
		GOOS:     a.GOOS,
		OptedIn:  a.wipeOptIn,
		Hostname: a.currentHostname,
		Probe: func(ctx context.Context) wipe.Readiness {
			a.mu.Lock()
			a.probe = nil
			a.mu.Unlock()
			return a.wipeReadiness(ctx)
		},
		Ack:  func(ctx context.Context) error { return a.client.Ack(ctx, c) },
		Exec: a.WipeExec,
	})
	return commands.Outcome{Status: o.Status, Output: o.Output}
}

func (a *Agent) runScript(ctx context.Context, c model.Command) commands.Outcome {
	o := scripts.Execute(ctx, c, scripts.Deps{
		Keys:  a.ScriptKeys,
		GOOS:  a.GOOS,
		Fetch: a.client.Fetch,
		MinVersion: func() string {
			a.mu.Lock()
			defer a.mu.Unlock()
			return a.st.ScriptBundleVersion
		},
		SetMinVersion: func(v string) error {
			a.mu.Lock()
			defer a.mu.Unlock()
			a.st.ScriptBundleVersion = v
			return a.save()
		},
		WorkDir: a.Paths.StateDir,
		Now:     a.serverNow,
		Runner:  a.ScriptRunner,
	})
	return commands.Outcome{Status: o.Status, Output: o.Output, ExitCode: o.ExitCode}
}

func (a *Agent) isolateHost(ctx context.Context, c model.Command) commands.Outcome {
	if a.Signin == nil {
		return commands.Outcome{Status: "rejected", Output: "suspend sign-in is not supported on this platform"}
	}
	incidentID, _ := commands.IncidentIDParam(c.Params)
	if incidentID == "" {
		incidentID = c.ID
	}
	out, err := a.Signin.Suspend(ctx, incidentID, c.ID)
	if err != nil {
		if errors.Is(err, signin.ErrNoLocalAdminPresent) {
			return commands.Outcome{Status: "rejected", Output: "refusing to suspend sign-in: no enabled local " +
				"administrator account would remain able to sign in (ERR_NO_LOCAL_ADMIN_PRESENT)"}
		}
		if errors.Is(err, signin.ErrLostModeActive) {
			return commands.Outcome{Status: "rejected", Output: err.Error()}
		}
		return commands.Outcome{Status: "failed", Output: strings.TrimSpace(out + "\n" + err.Error())}
	}
	return commands.Outcome{Status: "succeeded", Output: out}
}

func (a *Agent) restoreHost(ctx context.Context, c model.Command) commands.Outcome {
	if a.Signin == nil {
		return commands.Outcome{Status: "rejected", Output: "restore sign-in is not supported on this platform"}
	}
	out, err := a.Signin.Restore(ctx)
	if err != nil {
		return commands.Outcome{Status: "failed", Output: strings.TrimSpace(out + "\n" + err.Error())}
	}
	return commands.Outcome{Status: "succeeded", Output: out}
}

// maybeReenforceSignin re-asserts the suspend-sign-in restriction and banner
// while it's active, correcting drift (e.g. a GPO refresh), the same way
// maybeRelock does for lost mode.
func (a *Agent) maybeReenforceSignin(ctx context.Context) {
	if a.Signin == nil {
		return
	}
	a.mu.Lock()
	due := !time.Now().Before(a.nextSigninReenforce)
	if due {
		a.nextSigninReenforce = time.Now().Add(signin.ReenforceInterval)
	}
	a.mu.Unlock()
	if !due {
		return
	}
	if acted, out := a.Signin.Reenforce(ctx); acted {
		slog.Info("suspend sign-in: re-enforcement checked", "result", out)
	}
}

type agentError string

func (e agentError) Error() string { return string(e) }

const errLostModeUnavailable = agentError("lost mode is not available")
