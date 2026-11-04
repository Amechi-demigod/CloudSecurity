package osupdates

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "windows", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseWSUS(t *testing.T) {
	r, err := Parse(fixture(t, "os_updates_wsus.json"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "ok" || r.Error != "" {
		t.Fatalf("status %q error %q", r.Status, r.Error)
	}
	if r.Source != "wsus" || r.SourceDetail != "https://wsus.corp.example:8531" {
		t.Errorf("source %q %q", r.Source, r.SourceDetail)
	}
	if r.ServiceState != "running" || r.ServiceStartType != "manual" || !r.RebootPending {
		t.Errorf("service %q/%q reboot %v", r.ServiceState, r.ServiceStartType, r.RebootPending)
	}
	if r.LastSearchSuccessAt == nil || r.LastSearchSuccessAt.Format(time.RFC3339) != "2026-11-03T22:14:05Z" {
		t.Errorf("last search %v", r.LastSearchSuccessAt)
	}
	// the blank-title entry is dropped; Critical first, then other security, then the rest
	if len(r.Updates) != 3 {
		t.Fatalf("updates: %+v", r.Updates)
	}
	cu, net, def := r.Updates[0], r.Updates[1], r.Updates[2]
	if !slices.Equal(cu.KBIDs, []string{"KB5044284"}) || cu.Classification != "security" || cu.MsrcSeverity != "Critical" {
		t.Errorf("cumulative update %+v", cu)
	}
	if !slices.Equal(cu.CVEIDs, []string{"CVE-2026-21001", "CVE-2026-21002"}) {
		t.Errorf("CVEs deduplicated, upper-cased and validated: %v", cu.CVEIDs)
	}
	if cu.RebootBehavior != "can_request" || cu.SizeBytes == nil || *cu.SizeBytes != 734003200 || cu.Downloaded {
		t.Errorf("reboot/size %+v", cu)
	}
	if cu.ReleaseDate == nil || *cu.ReleaseDate != "2026-10-08" || cu.UpdateID != "a1b2c3d4-0000-4000-8000-000000000001" {
		t.Errorf("date/id %+v", cu)
	}
	// single-element lists emitted as bare values; a localised name is matched by its id
	if !slices.Equal(net.KBIDs, []string{"KB5043050"}) || net.Classification != "security" ||
		!slices.Equal(net.CVEIDs, []string{"CVE-2026-20001"}) || net.RebootBehavior != "always" {
		t.Errorf(".NET update %+v", net)
	}
	if def.Classification != "definition" || def.MsrcSeverity != "" || def.UpdateID != "6b4d1f0a-1e2b-4c3d-9e8f-0a1b2c3d4e5f" {
		t.Errorf("definition update %+v", def)
	}
}

func TestParseFailedSearchKeepsFacts(t *testing.T) {
	r, err := Parse(fixture(t, "os_updates_disabled.json"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "failed" || !strings.Contains(r.Error, "0x80070422") || len(r.Updates) != 0 || r.Updates == nil {
		t.Fatalf("%+v", r)
	}
	if r.ServiceStartType != "disabled" || r.ServiceState != "stopped" {
		t.Errorf("service %q/%q", r.ServiceState, r.ServiceStartType)
	}
	if r.Source != "wufb" || r.SourceDetail != "policies: gpo:DeferQualityUpdates, mdm:DeferFeatureUpdatesPeriodInDays" {
		t.Errorf("source %q %q", r.Source, r.SourceDetail)
	}
	if r.LastSearchSuccessAt != nil {
		t.Errorf("1601 placeholder date must be dropped: %v", r.LastSearchSuccessAt)
	}
}

func TestParsePS51WrappedListsAndMicrosoftUpdate(t *testing.T) {
	b := fixture(t, "os_updates_mu_ps51.json") // starts with a UTF-8 BOM, as PowerShell 5.1 may print
	if !strings.HasPrefix(string(b), bom) {
		t.Fatal("fixture lost its byte order mark")
	}
	r, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "ok" || r.Source != "microsoft_update" || r.SourceDetail != "Microsoft Update" {
		t.Errorf("%q %q %q", r.Status, r.Source, r.SourceDetail)
	}
	if r.ServiceStartType != "delayed_auto" || !r.RebootPending {
		t.Errorf("start type %q reboot %v", r.ServiceStartType, r.RebootPending)
	}
	if len(r.Updates) != 1 || !slices.Equal(r.Updates[0].KBIDs, []string{"KB890830"}) ||
		r.Updates[0].Classification != "update_rollup" || len(r.Updates[0].CVEIDs) != 0 {
		t.Errorf("%+v", r.Updates)
	}
}

func TestParseResultCodesAndGarbage(t *testing.T) {
	for _, tc := range []struct {
		in, status, err string
	}{
		{`{"result_code":4,"updates":[]}`, "failed", "result code 4"},
		{`{"result_code":5}`, "failed", "result code 5"},
		{`{}`, "failed", "no result"},
		{`{"result_code":2,"updates":null}`, "ok", ""},
	} {
		r, err := Parse([]byte(tc.in))
		if err != nil || r.Status != tc.status || !strings.Contains(r.Error, tc.err) {
			t.Errorf("%s: %+v %v", tc.in, r, err)
		}
	}
	for _, bad := range []string{"", "   ", "Get-Service : access denied", `{"updates":"x"`} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
}

func TestSourceFallbacks(t *testing.T) {
	one := func(v int) *int { return &v }
	for _, tc := range []struct {
		r          raw
		src, extra string
	}{
		{raw{}, "unknown", ""},
		{func() raw { var r raw; r.Policy.WUServer = "http://wsus:8530"; return r }(), "unknown", ""},
		{func() raw {
			var r raw
			r.Policy.WUServer, r.Policy.UseWUServer, r.Policy.WUfB = "http://wsus:8530", one(1), strList{"gpo:TargetReleaseVersion"}
			return r
		}(), "wsus", "also set"},
	} {
		src, detail := source(tc.r)
		if src != tc.src || !strings.Contains(detail, tc.extra) {
			t.Errorf("%+v: %q %q", tc.r.Policy, src, detail)
		}
	}
}

func TestLimitsAndNormalisation(t *testing.T) {
	var ups []string
	for i := range MaxUpdates + 50 {
		sev := ""
		if i == MaxUpdates+40 {
			sev = "Critical" // sorted to the front, so it survives the cap
		}
		ups = append(ups, fmt.Sprintf(`{"title":"Update %d","kb":["KB%d"],"msrc":%q,"date":"1999-12-31","reboot":7,"size":-1}`, i, 1000000+i, sev))
	}
	r, err := Parse([]byte(`{"result_code":2,"updates":[` + strings.Join(ups, ",") + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Updates) != MaxUpdates || r.Updates[0].MsrcSeverity != "Critical" {
		t.Fatalf("%d updates, first %+v", len(r.Updates), r.Updates[0])
	}
	u := r.Updates[1]
	if u.ReleaseDate != nil || u.RebootBehavior != "" || u.SizeBytes != nil || u.Classification != "other" {
		t.Errorf("invalid values must be dropped: %+v", u)
	}
	long := strings.Repeat("é", 600)
	r, _ = Parse([]byte(`{"result_code":2,"updates":[{"title":"` + long + `","kb":["KBxyz","12","KB1234567890123"],"msrc":"Severe"}]}`))
	if n := len([]rune(r.Updates[0].Title)); n != 512 || len(r.Updates[0].KBIDs) != 0 || r.Updates[0].MsrcSeverity != "" {
		t.Errorf("title %d runes, kbs %v, msrc %q", n, r.Updates[0].KBIDs, r.Updates[0].MsrcSeverity)
	}
	if got := snake("StartPending"); got != "start_pending" {
		t.Errorf("snake: %q", got)
	}
	if got := startType("Boot", false); got != "unknown" {
		t.Errorf("startType: %q", got)
	}
}

// The report must match the server schema's field names exactly (it rejects unknown fields).
func TestReportJSONShape(t *testing.T) {
	r, _ := Parse(fixture(t, "os_updates_wsus.json"))
	b, _ := json.Marshal(r)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	want := []string{"duration_seconds", "error", "last_install_success_at", "last_search_success_at", "reboot_pending",
		"scanned_at", "schema_version", "service_start_type", "service_state", "source", "source_detail", "status",
		"trigger", "updates"}
	var got []string
	for k := range m {
		got = append(got, k)
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("keys %v", got)
	}
	u := m["updates"].([]any)[0].(map[string]any)
	if len(u) != 10 || u["release_date"] != "2026-10-08" {
		t.Errorf("update keys %v", u)
	}
	if f := Failed(fmt.Errorf("powershell.exe timed out after 30m0s")); f.Status != "failed" || f.Updates == nil ||
		!strings.Contains(f.Error, "timed out") {
		t.Errorf("%+v", f)
	}
}

func TestSchedule(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	mid := func() float64 { return 0.5 }
	low := func() float64 { return 0 }
	if got := NextScan(time.Time{}, now, low); !got.Equal(now.Add(StartDelayMin)) {
		t.Errorf("never scanned: %v", got)
	}
	if got := NextScan(now.Add(-time.Hour), now, mid); !got.Equal(now.Add(11 * time.Hour)) {
		t.Errorf("scanned an hour ago: %v", got)
	}
	// long overdue (agent was off): soon after start, never immediately
	if got := NextScan(now.Add(-72*time.Hour), now, low); !got.Equal(now.Add(StartDelayMin)) {
		t.Errorf("overdue: %v", got)
	}
	if got := After(now, low); !got.Equal(now.Add(Interval - Jitter)) {
		t.Errorf("after: %v", got)
	}
	for range 100 {
		d := After(now, nil).Sub(now)
		if d < Interval-Jitter || d > Interval+Jitter {
			t.Fatalf("jitter out of range: %v", d)
		}
	}
}
