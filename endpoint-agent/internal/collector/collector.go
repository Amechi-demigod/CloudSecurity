// Package collector is the dedicated directory collector (cmd/cnapp-collector):
// a separate program from the endpoint agent with its own identity, its own
// API (/api/collector/*) and a command handler that knows ONLY directory work.
//
// It imports the directory export (internal/directory), the API client, the
// state store and the signed self-update - and nothing that can act on a
// machine: no scripts, remote sessions, isolation, lock, wipe or log
// collection are compiled in (cmd/cnapp-collector's tests check the import
// graph). Unknown command types are rejected before anything else happens.
package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/backoff"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/directory"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/state"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/update"
)

// Command types (mirrors backend app/directory/collectors.py COMMAND_TYPES).
const (
	CmdDirectorySync  = directory.CommandType
	CmdDiagnostics    = "collector_diagnostics"
	CmdHealth         = "collector_health"
	CmdCheckForUpdate = "check_for_update"
)

// AllowedCommands is the complete command set of the collector.
var AllowedCommands = []string{CmdDirectorySync, CmdDiagnostics, CmdHealth, CmdCheckForUpdate}

// Features advertised in the heartbeat.
const Features = "directory_sync,collector_diagnostics,sealed_ldap"

const (
	heartbeatInterval = 5 * time.Minute
	pollInterval      = 60 * time.Second
)

var idRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Facts describe the collector's host (heartbeat; see facts_windows.go).
type Facts struct {
	Hostname           string `json:"hostname"`
	DNSHostname        string `json:"dns_hostname"`
	Domain             string `json:"domain"`
	OSName             string `json:"os_name"`
	OSVersion          string `json:"os_version"`
	Architecture       string `json:"architecture"`
	Version            string `json:"version"`
	RunAs              string `json:"run_as"`
	RunAsKind          string `json:"run_as_kind"`
	IsDomainController bool   `json:"is_domain_controller"`
	Features           string `json:"features"`
}

// API is the server side (implemented by internal/client with prefix /api/collector).
type API interface {
	PostJSON(ctx context.Context, path string, in, out any) error
	GetJSON(ctx context.Context, path string, out any) error
	UploadDirectoryBatch(ctx context.Context, path, token string, gz []byte) error
}

// Outcome of one command.
type Outcome struct {
	Status     string // succeeded | failed | rejected
	Output     string
	ResultData any
}

// Collector runs the heartbeat / command loop.
type Collector struct {
	API         API
	Paths       state.Paths
	ID          string
	Facts       func() Facts
	Diagnostics func(identity string) *directory.Diagnostics
	Connect     directory.Connector // nil: the real LDAP backends
	Updater     *update.Updater
	Restart     func()

	mu        sync.Mutex
	st        *state.State
	skew      time.Duration
	offer     *update.Offer
	dirBusy   atomic.Bool
	dirWG     sync.WaitGroup
	baseCtx   context.Context
	nextHeart time.Time
}

// Allowed reports whether t is a collector command.
func Allowed(t string) bool { return slices.Contains(AllowedCommands, t) }

// Validate checks a delivered command: type in the allow-list, bound to this
// collector, id / nonce present, not expired, parameters valid.
func Validate(c model.Command, collectorID string, now time.Time) error {
	if !Allowed(c.Type) {
		return fmt.Errorf("command type %q is not supported by the directory collector (it only does directory work)", c.Type)
	}
	if c.DeviceID != collectorID {
		return errors.New("command is bound to another collector")
	}
	if !idRe.MatchString(c.ID) || len(c.Nonce) < 16 {
		return errors.New("command id/nonce missing")
	}
	if !c.ExpiresAt.IsZero() && now.After(c.ExpiresAt) {
		return fmt.Errorf("command expired at %s", c.ExpiresAt.Format(time.RFC3339))
	}
	switch c.Type {
	case CmdDirectorySync:
		_, err := directory.ParseParams(c.Params)
		return err
	case CmdDiagnostics:
		_, err := directory.ParseDiagParams(c.Params)
		return err
	default:
		if len(c.Params) != 0 {
			return fmt.Errorf("%s takes no parameters", c.Type)
		}
	}
	return nil
}

// Heartbeat sends the host facts; the response may carry a signed-update offer.
func (c *Collector) Heartbeat(ctx context.Context) error {
	var resp struct {
		ServerTime time.Time     `json:"server_time"`
		Update     *update.Offer `json:"update"`
	}
	if err := c.API.PostJSON(ctx, "/api/collector/heartbeat", map[string]any{"facts": c.Facts()}, &resp); err != nil {
		return err
	}
	c.mu.Lock()
	if !resp.ServerTime.IsZero() {
		c.skew = time.Until(resp.ServerTime)
	}
	c.offer = resp.Update
	c.mu.Unlock()
	if c.Updater != nil {
		c.Updater.MarkHealthy()
		c.Updater.ReportOutcome(ctx)
	}
	return nil
}

func (c *Collector) serverNow() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.skew)
}

// Poll fetches and executes pending commands (each at most once).
func (c *Collector) Poll(ctx context.Context) error {
	var list model.CommandList
	if err := c.API.GetJSON(ctx, "/api/collector/commands", &list); err != nil {
		return err
	}
	for _, cmd := range list.Commands {
		c.handle(ctx, cmd)
	}
	return nil
}

func (c *Collector) report(ctx context.Context, cmd model.Command, o Outcome) {
	body := map[string]any{"nonce": cmd.Nonce, "status": o.Status, "output": truncate(o.Output, 8000)}
	if o.ResultData != nil {
		body["result_data"] = o.ResultData
	}
	if err := c.API.PostJSON(ctx, "/api/collector/commands/"+cmd.ID+"/result", body, nil); err != nil {
		slog.Warn("reporting command result failed", "command_id", cmd.ID, "err", err)
	}
}

func (c *Collector) handle(ctx context.Context, cmd model.Command) {
	log := slog.With("command_id", cmd.ID, "type", cmd.Type)
	if err := Validate(cmd, c.ID, c.serverNow()); err != nil {
		log.Warn("command rejected", "err", err)
		c.report(ctx, cmd, Outcome{Status: "rejected", Output: err.Error()})
		return
	}
	if c.st != nil {
		c.mu.Lock()
		fresh := c.st.MarkExecuted(cmd.ID)
		err := state.Save(c.Paths, c.st)
		c.mu.Unlock()
		if !fresh {
			log.Warn("command already executed; ignoring replay")
			return
		}
		if err != nil {
			c.report(ctx, cmd, Outcome{Status: "failed", Output: "collector could not persist its state: " + err.Error()})
			return
		}
	}
	log.Info("executing command")
	o := c.Execute(ctx, cmd)
	log.Info("command finished", "status", o.Status)
	c.report(ctx, cmd, o)
}

// Execute runs a validated command. Anything outside AllowedCommands is
// rejected here too (defence in depth).
func (c *Collector) Execute(ctx context.Context, cmd model.Command) Outcome {
	switch cmd.Type {
	case CmdDirectorySync:
		return c.directorySync(cmd)
	case CmdDiagnostics:
		return c.diagnostics(ctx, cmd)
	case CmdHealth:
		b, _ := json.Marshal(c.Facts())
		return Outcome{Status: "succeeded", Output: string(b)}
	case CmdCheckForUpdate:
		if c.Updater == nil {
			return Outcome{Status: "failed", Output: "self-update is disabled (not running as the service, or no release key)"}
		}
		if err := c.Heartbeat(ctx); err != nil {
			return Outcome{Status: "failed", Output: "heartbeat failed: " + err.Error()}
		}
		c.mu.Lock()
		o := c.offer
		c.mu.Unlock()
		if o == nil {
			return Outcome{Status: "succeeded", Output: "no update offered"}
		}
		return Outcome{Status: "succeeded", Output: "update to " + o.Version + " offered; verifying and installing now"}
	}
	return Outcome{Status: "rejected", Output: "not a collector command"}
}

func (c *Collector) directorySync(cmd model.Command) Outcome {
	p, err := directory.ParseParams(cmd.Params)
	if err != nil {
		return Outcome{Status: "rejected", Output: err.Error()}
	}
	if !c.dirBusy.CompareAndSwap(false, true) {
		return Outcome{Status: "failed", Output: "a directory sync is already running on this collector"}
	}
	connect := c.Connect
	if connect == nil {
		connect = directory.Connect
	}
	c.mu.Lock()
	base := c.baseCtx
	c.mu.Unlock()
	if base == nil {
		base = context.Background()
	}
	r := &directory.Runner{Connect: connect, Upload: c.API}
	c.dirWG.Add(1)
	go func() {
		defer c.dirWG.Done()
		defer c.dirBusy.Store(false)
		res := r.Run(base, p)
		slog.Info("directory sync finished", "run_id", p.RunID, "status", res.Status, "computers", res.Totals.Computers,
			"users", res.Totals.Users, "server", res.Server, "error", res.Error)
	}()
	return Outcome{Status: "succeeded", Output: "directory sync started (run " + p.RunID + ")"}
}

func (c *Collector) diagnostics(ctx context.Context, cmd model.Command) Outcome {
	p, err := directory.ParseDiagParams(cmd.Params)
	if err != nil {
		return Outcome{Status: "rejected", Output: err.Error()}
	}
	mk := c.Diagnostics
	if mk == nil {
		mk = directory.DefaultDiagnostics
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	res := mk(c.Facts().RunAs).Run(ctx, p)
	o := Outcome{Status: "succeeded", Output: "all checks passed", ResultData: res}
	if !res.OK() {
		o.Status, o.Output = "failed", "one or more checks failed"
	}
	return o
}

// WaitDirectorySync waits up to d for a running sync.
func (c *Collector) WaitDirectorySync(d time.Duration) {
	done := make(chan struct{})
	go func() { c.dirWG.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
	}
}

// Run loops until ctx ends: heartbeat every 5 minutes, command poll every
// minute, a pending signed update when offered.
func (c *Collector) Run(ctx context.Context) error {
	st, err := state.Load(c.Paths)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.st, c.baseCtx = st, ctx
	c.mu.Unlock()
	defer c.WaitDirectorySync(20 * time.Second)
	pol := backoff.Default
	nextHeart, nextPoll := time.Now(), time.Now()
	hf, pf := 0, 0
	for {
		wait := min(time.Until(nextHeart), time.Until(nextPoll))
		if wait > 0 {
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return nil
			case <-t.C:
			}
		}
		if ctx.Err() != nil {
			return nil
		}
		if !time.Now().Before(nextHeart) {
			hf, nextHeart = next(c.Heartbeat(ctx), hf, heartbeatInterval, pol, "heartbeat")
		}
		if !time.Now().Before(nextPoll) {
			pf, nextPoll = next(c.Poll(ctx), pf, pollInterval, pol, "command poll")
		}
		if c.maybeUpdate(ctx) {
			if c.Restart != nil {
				c.Restart()
			}
			return nil
		}
	}
}

func next(err error, failures int, interval time.Duration, pol backoff.Policy, what string) (int, time.Time) {
	if err == nil {
		return 0, time.Now().Add(interval)
	}
	failures++
	d := pol.Retry(failures)
	slog.Warn(what+" failed; backing off", "err", err, "attempt", failures, "retry_in", d.Round(time.Second))
	return failures, time.Now().Add(d)
}

func (c *Collector) maybeUpdate(ctx context.Context) bool {
	c.mu.Lock()
	o := c.offer
	c.offer = nil
	c.mu.Unlock()
	if o == nil || c.Updater == nil || c.dirBusy.Load() {
		if o != nil && c.dirBusy.Load() {
			c.mu.Lock()
			c.offer = o // after the running sync
			c.mu.Unlock()
		}
		return false
	}
	err := c.Updater.Apply(ctx, *o)
	if errors.Is(err, update.ErrRestartRequired) {
		return true
	}
	if err != nil {
		slog.Warn("collector update not applied", "version", o.Version, "err", err)
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
