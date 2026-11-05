package agent

import (
	"context"
	"log/slog"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/commands"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/osupdates"
)

// Retries of the report upload after a search (the search itself is not repeated).
var defaultOSUpdateRetryDelays = []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute}

func (a *Agent) osUpdatesSupported() bool {
	return a.GOOS == "windows" && (osupdates.Supported || a.OSUpdateScan != nil)
}

// scanOSUpdates (command scan_os_updates, "Check for updates now") starts a
// read-only Windows Update search in the background so command polling and
// check-ins continue; the report is uploaded when it completes.
func (a *Agent) scanOSUpdates(_ context.Context, _ model.Command) commands.Outcome {
	if !a.osUpdatesSupported() {
		return commands.Outcome{Status: "rejected", Output: osupdates.ErrUnsupported.Error()}
	}
	if !a.startOSUpdateScan("command") {
		return commands.Outcome{Status: "succeeded", Output: "a Windows Update search is already running; its report follows when it completes"}
	}
	return commands.Outcome{Status: "succeeded", Output: "Windows Update search started; the report follows when it completes (searches can take several minutes)"}
}

// maybeScanOSUpdates starts the scheduled search when it is due (about every
// 12 hours, jittered; the first one shortly after the agent starts).
func (a *Agent) maybeScanOSUpdates() {
	if !a.osUpdatesSupported() {
		return
	}
	now := time.Now()
	a.mu.Lock()
	if a.nextOSUpdateScan.IsZero() {
		a.nextOSUpdateScan = osupdates.NextScan(a.st.OSUpdatesLastScan, now, nil)
	}
	due := !now.Before(a.nextOSUpdateScan)
	a.mu.Unlock()
	if due {
		a.startOSUpdateScan("schedule")
	}
}

// startOSUpdateScan runs one search in the background unless one is running.
func (a *Agent) startOSUpdateScan(trigger string) bool {
	if !a.osUpdRunning.CompareAndSwap(false, true) {
		return false
	}
	a.mu.Lock()
	base := a.baseCtx
	// No second scheduled search while this one runs; set properly when it ends.
	a.nextOSUpdateScan = time.Now().Add(osupdates.Timeout)
	a.mu.Unlock()
	if base == nil {
		base = context.Background()
	}
	scan := a.OSUpdateScan
	if scan == nil {
		scan = osupdates.Scan
	}
	a.osUpdWG.Add(1)
	go func() {
		defer a.osUpdWG.Done()
		defer a.osUpdRunning.Store(false)
		rep := a.runOSUpdateScan(base, scan, trigger)
		finished := time.Now()
		a.mu.Lock()
		a.st.OSUpdatesLastScan = finished.UTC()
		a.nextOSUpdateScan = osupdates.After(finished, nil)
		if err := a.save(); err != nil {
			slog.Warn("saving the OS update scan time failed", "err", err)
		}
		a.mu.Unlock()
		if base.Err() != nil {
			return // agent stopping: nothing useful to report
		}
		a.uploadOSUpdates(base, rep)
	}()
	return true
}

func (a *Agent) runOSUpdateScan(ctx context.Context, scan func(context.Context) (model.OSUpdateReport, error),
	trigger string) model.OSUpdateReport {
	start := time.Now()
	slog.Info("Windows Update search started", "trigger", trigger)
	sctx, cancel := context.WithTimeout(ctx, osupdates.Timeout)
	defer cancel()
	rep, err := scan(sctx)
	if err != nil {
		rep = osupdates.Failed(err)
	}
	rep.SchemaVersion, rep.Trigger, rep.ScannedAt = 1, trigger, time.Now().UTC()
	secs := int(time.Since(start).Seconds())
	rep.DurationSeconds = &secs
	if rep.Updates == nil {
		rep.Updates = []model.MissingUpdate{}
	}
	slog.Info("Windows Update search finished", "status", rep.Status, "missing", len(rep.Updates),
		"source", rep.Source, "reboot_pending", rep.RebootPending, "duration", time.Since(start).Round(time.Second),
		"error", rep.Error)
	return rep
}

func (a *Agent) uploadOSUpdates(ctx context.Context, rep model.OSUpdateReport) {
	delays := a.osUpdateRetryDelays
	if delays == nil {
		delays = defaultOSUpdateRetryDelays
	}
	for attempt := 0; ; attempt++ {
		err := a.client.ReportOSUpdates(ctx, &rep)
		if err == nil {
			return
		}
		if attempt >= len(delays) || ctx.Err() != nil {
			slog.Warn("uploading the OS update report failed; the next search reports again", "err", err)
			return
		}
		slog.Warn("uploading the OS update report failed; retrying", "err", err, "retry_in", delays[attempt])
		select {
		case <-ctx.Done():
			return
		case <-time.After(delays[attempt]):
		}
	}
}

// OSUpdateScanBusy reports whether a Windows Update search is running.
func (a *Agent) OSUpdateScanBusy() bool { return a.osUpdRunning.Load() }

// WaitOSUpdateScan waits up to d for a running search and its upload (tests).
func (a *Agent) WaitOSUpdateScan(d time.Duration) bool {
	done := make(chan struct{})
	go func() { a.osUpdWG.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}
