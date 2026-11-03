package agent

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/commands"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/directory"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
)

// directorySync (command directory_sync) starts a directory export in the
// background so command polling continues; the command result only reports
// that it started. Progress and the outcome go to the server with the
// batches (internal/directory). One sync at a time per agent.
func (a *Agent) directorySync(ctx context.Context, c model.Command) commands.Outcome {
	p, err := directory.ParseParams(c.Params)
	if err != nil {
		return commands.Outcome{Status: "rejected", Output: err.Error()}
	}
	if !a.dirRunning.CompareAndSwap(false, true) {
		return commands.Outcome{Status: "failed", Output: "a directory sync is already running on this collector"}
	}
	a.mu.Lock()
	base := a.baseCtx
	a.mu.Unlock()
	if base == nil {
		base = ctx
	}
	connect := a.DirectoryConnect
	if connect == nil {
		connect = directory.Connect
	}
	r := &directory.Runner{Connect: connect, Upload: a.client, RetryDelays: a.directoryRetryDelays}
	a.dirWG.Add(1)
	go func() {
		defer a.dirWG.Done()
		defer a.dirRunning.Store(false)
		log := slog.With("run_id", p.RunID, "source_id", p.SourceID)
		log.Info("directory sync started", "domain", p.Domain, "security", p.Security, "auth", p.Auth,
			"scopes", p.Scopes, "test", p.Test)
		res := r.Run(base, p)
		log.Info("directory sync finished", "status", res.Status, "computers", res.Totals.Computers,
			"users", res.Totals.Users, "batches", res.Batches, "truncated", res.Truncated, "server", res.Server,
			"error", res.Error)
	}()
	return commands.Outcome{Status: "succeeded", Output: fmt.Sprintf("directory sync started (run %s)", p.RunID)}
}

// DirectorySyncBusy reports whether a directory sync is running.
func (a *Agent) DirectorySyncBusy() bool { return a.dirRunning.Load() }

// WaitDirectorySync waits up to d for a running sync (e.g. on shutdown, so it
// can report its final "cancelled" batch). It returns false on timeout.
func (a *Agent) WaitDirectorySync(d time.Duration) bool {
	done := make(chan struct{})
	go func() { a.dirWG.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}
