// Package agent runs the check-in / command-poll loop.
package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/backoff"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/client"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/collect"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/commands"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/state"
)

const (
	defaultInterval    = 15 * time.Minute
	defaultCommandPoll = 60 * time.Second
	// After the server rejects the credential (revoked / re-enrolled elsewhere)
	// the agent keeps running but only retries hourly, until it is re-enrolled.
	unauthorizedRetry = time.Hour
)

// Agent is an enrolled agent.
type Agent struct {
	Paths   state.Paths
	Restart func() // called after restart_agent has been reported

	mu     sync.Mutex
	st     *state.State
	client *client.Client
	skew   time.Duration // server time - local time
	policy backoff.Policy
	// Collect is replaceable in tests.
	Collect func(ctx context.Context, o collect.Options) *model.Report
	Lock    func(ctx context.Context) (string, error)
}

// Load reads the enrollment state and builds the API client.
func Load(p state.Paths) (*Agent, error) {
	st, err := state.Load(p)
	if err != nil {
		return nil, err
	}
	c, err := client.New(st.ServerURL, st.DeviceSecret, client.Options{InsecureDev: st.InsecureDev, CAFile: st.CAFile})
	if err != nil {
		return nil, err
	}
	return &Agent{Paths: p, st: st, client: c, policy: backoff.Default, Collect: collect.Collect, Lock: commands.Lock}, nil
}

// State returns a copy of the current state.
func (a *Agent) State() state.State {
	a.mu.Lock()
	defer a.mu.Unlock()
	return *a.st
}

func (a *Agent) save() error {
	return state.Save(a.Paths, a.st)
}

func (a *Agent) interval() time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.st.CheckInIntervalSeconds >= commands.MinIntervalSeconds {
		return time.Duration(a.st.CheckInIntervalSeconds) * time.Second
	}
	return defaultInterval
}

func (a *Agent) pollInterval() time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.st.CommandPollSeconds >= 15 {
		return time.Duration(a.st.CommandPollSeconds) * time.Second
	}
	return defaultCommandPoll
}

func (a *Agent) noteServerTime(t time.Time) {
	if !t.IsZero() {
		a.mu.Lock()
		a.skew = time.Until(t)
		a.mu.Unlock()
	}
}

func (a *Agent) serverNow() time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()
	return time.Now().Add(a.skew)
}

// CheckIn collects a full report and sends it.
func (a *Agent) CheckIn(ctx context.Context) error {
	start := time.Now()
	r := a.Collect(ctx, collect.Options{Software: true})
	resp, err := a.client.CheckIn(ctx, r)
	if err != nil {
		return err
	}
	a.noteServerTime(resp.ServerTime)
	a.mu.Lock()
	a.st.LastCheckIn = time.Now().UTC()
	err = a.save()
	a.mu.Unlock()
	slog.Info("check-in complete", "duration", time.Since(start).Round(time.Millisecond), "issues", resp.Issues,
		"pending_commands", resp.PendingCommands, "collector_errors", len(r.Errors))
	return err
}

// PollCommands fetches pending commands and executes them (at most once each).
func (a *Agent) PollCommands(ctx context.Context) error {
	list, err := a.client.Commands(ctx)
	if err != nil {
		return err
	}
	a.noteServerTime(list.ServerTime)
	for _, c := range list.Commands {
		a.handle(ctx, c)
	}
	return nil
}

func (a *Agent) handle(ctx context.Context, c model.Command) {
	log := slog.With("command_id", c.ID, "type", c.Type)
	a.mu.Lock()
	deviceID := a.st.DeviceID
	a.mu.Unlock()
	if err := commands.Validate(c, deviceID, a.serverNow()); err != nil {
		log.Warn("command rejected", "err", err)
		if rerr := a.client.Result(ctx, c, "rejected", err.Error()); rerr != nil {
			log.Warn("reporting rejection failed", "err", rerr)
		}
		return
	}
	// Persist "executed" before running so a crash mid-way never re-runs it.
	a.mu.Lock()
	fresh := a.st.MarkExecuted(c.ID)
	serr := a.save()
	a.mu.Unlock()
	if !fresh {
		log.Warn("command already executed; ignoring replay")
		return
	}
	if serr != nil {
		log.Error("cannot persist command state; refusing to execute", "err", serr)
		_ = a.client.Result(ctx, c, "failed", "agent could not persist its state: "+serr.Error())
		return
	}
	log.Info("executing command")
	out := commands.Execute(ctx, c, commands.Deps{
		CheckIn:     a.CheckIn,
		BuildLogs:   a.BuildLogs,
		UploadLogs:  a.client.UploadLogs,
		SetInterval: a.setInterval,
		Lock:        a.Lock,
	}, a.Restart)
	log.Info("command finished", "status", out.Status, "output", out.Output)
	if err := a.client.Result(ctx, c, out.Status, out.Output); err != nil {
		log.Warn("reporting result failed", "err", err)
	}
	if out.After != nil {
		out.After()
	}
}

func (a *Agent) setInterval(seconds int) error {
	if seconds < commands.MinIntervalSeconds || seconds > commands.MaxIntervalSeconds {
		return fmt.Errorf("interval %d out of range", seconds)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.st.CheckInIntervalSeconds = seconds
	return a.save()
}

// Run loops until ctx is cancelled: a full check-in every interval (with
// jitter) and a lightweight command poll every ~60s, each with exponential
// backoff on failure.
func (a *Agent) Run(ctx context.Context) error {
	st := a.State()
	slog.Info("agent started", "device_id", st.DeviceID, "server", st.ServerURL, "interval", a.interval())
	nextCheckIn := time.Now()
	nextPoll := time.Now().Add(5 * time.Second)
	checkInFailures, pollFailures := 0, 0
	for {
		wait := time.Until(nextCheckIn)
		if w := time.Until(nextPoll); w < wait {
			wait = w
		}
		if wait > 0 {
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				slog.Info("agent stopping")
				return nil
			case <-t.C:
			}
		}
		if ctx.Err() != nil {
			return nil
		}
		if !time.Now().Before(nextCheckIn) {
			err := a.CheckIn(ctx)
			checkInFailures, nextCheckIn = a.schedule(err, checkInFailures, a.interval(), "check-in")
		}
		if !time.Now().Before(nextPoll) {
			err := a.PollCommands(ctx)
			pollFailures, nextPoll = a.schedule(err, pollFailures, a.pollInterval(), "command poll")
		}
	}
}

func (a *Agent) schedule(err error, failures int, interval time.Duration, what string) (int, time.Time) {
	if err == nil {
		return 0, time.Now().Add(a.policy.Next(interval))
	}
	if errors.Is(err, context.Canceled) {
		return failures, time.Now()
	}
	failures++
	delay := a.policy.Retry(failures)
	if client.IsUnauthorized(err) {
		delay = unauthorizedRetry
		slog.Error(what+" rejected: this device must be re-enrolled (cnapp-agent enroll)", "err", err)
	} else {
		slog.Warn(what+" failed; backing off", "err", err, "attempt", failures, "retry_in", delay.Round(time.Second))
	}
	return failures, time.Now().Add(delay)
}
