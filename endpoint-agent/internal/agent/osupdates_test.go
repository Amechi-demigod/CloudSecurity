package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/state"
)

// fakeWUA stands in for the Windows Update search; release blocks it.
type fakeWUA struct {
	release chan struct{}
	calls   int
	err     error
}

func (w *fakeWUA) scan(ctx context.Context) (model.OSUpdateReport, error) {
	w.calls++
	if w.release != nil {
		select {
		case <-w.release:
		case <-ctx.Done():
			return model.OSUpdateReport{}, ctx.Err()
		}
	}
	if w.err != nil {
		return model.OSUpdateReport{}, w.err
	}
	d := "2026-10-08"
	return model.OSUpdateReport{Status: "ok", Source: "wsus", SourceDetail: "https://wsus.corp.example:8531",
		Updates: []model.MissingUpdate{{KBIDs: []string{"KB5044284"}, Title: "2026-10 Cumulative Update",
			Classification: "security", MsrcSeverity: "Critical", ReleaseDate: &d, CVEIDs: []string{}}}}, nil
}

func windowsAgent(t *testing.T) (*Agent, *fakeServer, *fakeWUA) {
	a, f := setup(t)
	w := &fakeWUA{}
	a.GOOS, a.OSUpdateScan = "windows", w.scan
	a.osUpdateRetryDelays = []time.Duration{time.Millisecond, time.Millisecond}
	return a, f, w
}

func TestScanOSUpdatesCommandRunsInBackground(t *testing.T) {
	a, f, w := windowsAgent(t)
	w.release = make(chan struct{})
	f.commands = []model.Command{command("c-wu", "scan_os_updates", nil)}
	if err := a.PollCommands(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	status, out := f.results["c-wu"], f.outputs["c-wu"]
	f.mu.Unlock()
	if status != "succeeded" || !strings.Contains(out, "started") {
		t.Fatalf("%s: %q", status, out)
	}
	if !a.OSUpdateScanBusy() {
		t.Fatal("the search should still be running (polling was not blocked)")
	}
	// A second request while one runs does not start another search.
	f.mu.Lock()
	f.commands = []model.Command{command("c-wu2", "scan_os_updates", nil)}
	f.mu.Unlock()
	_ = a.PollCommands(context.Background())
	f.mu.Lock()
	if f.results["c-wu2"] != "succeeded" || !strings.Contains(f.outputs["c-wu2"], "already running") {
		t.Errorf("concurrent: %q %q", f.results["c-wu2"], f.outputs["c-wu2"])
	}
	f.mu.Unlock()
	close(w.release)
	if !a.WaitOSUpdateScan(5 * time.Second) {
		t.Fatal("search did not finish")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if w.calls != 1 || len(f.osReports) != 1 {
		t.Fatalf("calls %d reports %d", w.calls, len(f.osReports))
	}
	rep := f.osReports[0]
	if rep["status"] != "ok" || rep["trigger"] != "command" || rep["schema_version"] != 1.0 || rep["scanned_at"] == "" ||
		rep["duration_seconds"] == nil || len(rep["updates"].([]any)) != 1 {
		t.Errorf("report %v", rep)
	}
	if st := a.State(); st.OSUpdatesLastScan.IsZero() {
		t.Error("last scan time not persisted")
	}
	// persisted across restarts: a reloaded agent does not search again right away
	st, _ := state.Load(a.Paths)
	if st.OSUpdatesLastScan.IsZero() || !a.nextOSUpdateScan.After(time.Now().Add(10*time.Hour)) {
		t.Errorf("next scan %v", a.nextOSUpdateScan)
	}
}

func TestScanOSUpdatesFailureIsReportedAndUploadRetried(t *testing.T) {
	a, f, w := windowsAgent(t)
	w.err = errors.New("powershell.exe timed out after 30m0s")
	f.osFail = 2 // the server is briefly unavailable
	if !a.startOSUpdateScan("schedule") {
		t.Fatal("not started")
	}
	if !a.WaitOSUpdateScan(5 * time.Second) {
		t.Fatal("did not finish")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.osReports) != 1 {
		t.Fatalf("reports %d", len(f.osReports))
	}
	rep := f.osReports[0]
	if rep["status"] != "failed" || !strings.Contains(rep["error"].(string), "timed out") || rep["trigger"] != "schedule" {
		t.Errorf("%v", rep)
	}
	if u, ok := rep["updates"].([]any); !ok || len(u) != 0 {
		t.Errorf("updates must be an empty list: %v", rep["updates"])
	}
}

func TestScheduledOSUpdateScan(t *testing.T) {
	a, f, w := windowsAgent(t)
	a.maybeScanOSUpdates() // first call only schedules (a few minutes after start)
	if w.calls != 0 || a.OSUpdateScanBusy() {
		t.Fatal("must not search immediately at start")
	}
	if d := time.Until(a.nextOSUpdateScan); d < 4*time.Minute || d > 31*time.Minute {
		t.Errorf("first search in %v", d)
	}
	a.mu.Lock()
	a.nextOSUpdateScan = time.Now().Add(-time.Second)
	a.mu.Unlock()
	a.maybeScanOSUpdates()
	if !a.WaitOSUpdateScan(5 * time.Second) {
		t.Fatal("did not finish")
	}
	f.mu.Lock()
	if w.calls != 1 || len(f.osReports) != 1 || f.osReports[0]["trigger"] != "schedule" {
		t.Errorf("calls %d reports %v", w.calls, f.osReports)
	}
	f.mu.Unlock()
	if d := time.Until(a.nextOSUpdateScan); d < 10*time.Hour || d > 14*time.Hour {
		t.Errorf("next search in %v", d)
	}
	a.maybeScanOSUpdates()
	if a.OSUpdateScanBusy() || w.calls != 1 {
		t.Error("searched again before it was due")
	}
}

func TestScanOSUpdatesUnsupportedOS(t *testing.T) {
	a, f := setup(t)
	a.GOOS = "darwin"
	f.commands = []model.Command{command("c-wu", "scan_os_updates", nil)}
	_ = a.PollCommands(context.Background())
	if f.results["c-wu"] != "rejected" || !strings.Contains(f.outputs["c-wu"], "Windows only") {
		t.Fatalf("%q %q", f.results["c-wu"], f.outputs["c-wu"])
	}
	a.maybeScanOSUpdates()
	if a.OSUpdateScanBusy() || !a.nextOSUpdateScan.IsZero() {
		t.Error("no schedule on macOS")
	}
	// parameters are not accepted
	f.commands = []model.Command{command("c-wu2", "scan_os_updates", map[string]any{"online": true})}
	a.GOOS = "windows"
	_ = a.PollCommands(context.Background())
	if f.results["c-wu2"] != "rejected" {
		t.Errorf("params: %q", f.results["c-wu2"])
	}
}
