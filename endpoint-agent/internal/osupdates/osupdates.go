// Package osupdates reports missing OS updates (Windows only for now): which
// applicable software updates the Windows Update Agent says are not installed,
// plus the update source, service state and pending restarts.
//
// It is read-only. The search runs through the Windows Update Agent API
// (Microsoft.Update.Session / IUpdateSearcher) with the machine's own
// configuration, so a WSUS-managed device asks its WSUS server, a Windows
// Update for Business device asks Microsoft, and nothing is downloaded or
// installed. Searches can take minutes, so the agent runs them in the
// background (scheduled about every 12 hours, or on demand with
// scan_os_updates) and uploads the report separately from check-ins.
//
// The search itself is a fixed, embedded PowerShell script emitting one JSON
// document (scan_windows.go), like the other Windows collectors; everything
// here is OS-independent and unit-tested against fixtures.
package osupdates

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
)

// CommandType is the on-demand "Check for updates now" command.
const CommandType = "scan_os_updates"

// Schedule and limits.
const (
	// Interval between scheduled searches, +/- Jitter.
	Interval = 12 * time.Hour
	Jitter   = time.Hour
	// A first search after the agent starts waits StartDelayMin..StartDelayMax
	// so a fleet restarting together does not hit WSUS at the same moment.
	StartDelayMin = 5 * time.Minute
	StartDelayMax = 30 * time.Minute
	// Timeout bounds one search (slow WSUS servers, first scans after setup).
	Timeout = 30 * time.Minute
	// MaxUpdates is the most updates reported (also enforced server-side).
	MaxUpdates = 1000
)

// ErrUnsupported is returned on operating systems without a report.
var ErrUnsupported = errors.New("OS update reports are Windows only in this version")

// NextScan returns when the next scheduled search is due: StartDelay after
// start when the agent never searched (or the last search is long overdue),
// otherwise Interval after the last one with jitter. r returns [0,1).
func NextScan(last, now time.Time, r func() float64) time.Time {
	if r == nil {
		r = rand.Float64
	}
	earliest := now.Add(StartDelayMin + time.Duration(r()*float64(StartDelayMax-StartDelayMin)))
	if last.IsZero() {
		return earliest
	}
	next := last.Add(Interval + time.Duration((2*r()-1)*float64(Jitter)))
	if next.Before(earliest) {
		return earliest
	}
	return next
}

// After returns the next scheduled search after one that just finished.
func After(finished time.Time, r func() float64) time.Time {
	if r == nil {
		r = rand.Float64
	}
	return finished.Add(Interval + time.Duration((2*r()-1)*float64(Jitter)))
}

// raw is the PowerShell script's output.
type raw struct {
	Service *struct {
		Status    string `json:"status"`
		StartType string `json:"start_type"`
		Delayed   *int   `json:"delayed"`
	} `json:"service"`
	ServiceError string `json:"service_error"`
	Policy       struct {
		WUServer    string  `json:"wu_server"`
		UseWUServer *int    `json:"use_wu_server"`
		WUfB        strList `json:"wufb"`
	} `json:"policy"`
	DefaultService *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"default_service"`
	Reboot struct {
		WUA   *bool `json:"wua"`
		WUKey bool  `json:"wu_key"`
		CBS   bool  `json:"cbs"`
	} `json:"reboot"`
	LastSearch    string          `json:"last_search"`
	LastInstall   string          `json:"last_install"`
	ResultCode    *int            `json:"result_code"`
	SearchError   string          `json:"search_error"`
	SearchHResult string          `json:"search_hresult"`
	Updates       list[rawUpdate] `json:"updates"`
}

type rawCategory struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

type rawUpdate struct {
	ID         string            `json:"id"`
	KB         strList           `json:"kb"`
	Title      string            `json:"title"`
	Categories list[rawCategory] `json:"categories"`
	Msrc       string            `json:"msrc"`
	Date       string            `json:"date"`
	CVEs       strList           `json:"cves"`
	Reboot     *int              `json:"reboot"`
	Size       *float64          `json:"size"`
	Downloaded bool              `json:"downloaded"`
}

// list decodes a JSON list that Windows PowerShell 5.1 may also have emitted
// as a single bare element, null, or {"value": [...], "Count": n}.
type list[T any] []T

func (l *list[T]) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	switch {
	case s == "null":
		*l = nil
		return nil
	case strings.HasPrefix(s, "["):
		var v []T
		err := json.Unmarshal(b, &v)
		*l = v
		return err
	case strings.HasPrefix(s, "{"):
		var wrapped struct {
			Value *[]T `json:"value"`
		}
		if json.Unmarshal(b, &wrapped) == nil && wrapped.Value != nil {
			*l = *wrapped.Value
			return nil
		}
	}
	var one T
	if err := json.Unmarshal(b, &one); err != nil {
		return err
	}
	*l = []T{one}
	return nil
}

type strList = list[string]

// Classification GUIDs (the UpdateClassification categories, the same on
// every Windows Update / WSUS source and not localised, unlike their names).
var classificationIDs = map[string]string{
	"0fa1201d-4330-4fa8-8ae9-b877473b6441": "security",
	"e6cf1350-c01b-414d-a61f-263d14d133b4": "critical",
	"e0789628-ce08-4437-be74-2495b842f43b": "definition",
	"b54e7d24-7add-428f-8b75-90a396fa584f": "feature_pack",
	"68c5b0a3-d1a6-4553-ae49-01d3a7827828": "service_pack",
	"b4832bd8-e735-4761-8daf-37f882276dab": "tool",
	"28bc880e-0592-4cbf-8f95-c79b17911d5f": "update_rollup",
	"cd5ffd1e-e932-4e3a-bf74-18bf0b1bbd83": "update",
	"ebfc1fc5-71a4-4f7b-9aca-3b9a503104a0": "driver",
	"3689bdc8-b205-4af4-8d4a-a63924c5e9d5": "upgrade",
}

// English names, used when a source reports a classification without its id.
var classificationNames = map[string]string{
	"security updates": "security", "critical updates": "critical", "definition updates": "definition",
	"feature packs": "feature_pack", "service packs": "service_pack", "tools": "tool",
	"update rollups": "update_rollup", "updates": "update", "drivers": "driver", "upgrades": "upgrade",
}

// Default Automatic Updates service ids (IUpdateService.ServiceID).
const (
	serviceMicrosoftUpdate = "7971f918-a847-4430-9279-4a52d1efe18d"
	serviceWindowsUpdate   = "9482f4b4-e343-43b6-b170-9a65bc822c77"
	serviceWSUS            = "3da21691-e39d-4da6-8a4b-b43877bcb1b7"
)

var (
	kbRe    = regexp.MustCompile(`^(?i:KB)?([0-9]{4,10})$`)
	cveRe   = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,8}$`)
	guidRe  = regexp.MustCompile(`^[0-9a-fA-F-]{1,64}$`)
	dateRe  = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	stateRe = regexp.MustCompile(`[^a-z_]`)
)

// bom is the UTF-8 byte order mark PowerShell may print first.
const bom = "\xef\xbb\xbf"

var msrcSeverities = []string{"Critical", "Important", "Moderate", "Low", "Unspecified"}

// Parse turns the script output into a report (ScannedAt, Trigger and
// DurationSeconds are set by the caller). A failed search is a report with
// Status "failed", not an error: the service state, source and restart flags
// are still worth reporting. Only unreadable output is an error.
func Parse(out []byte) (model.OSUpdateReport, error) {
	var r raw
	s := strings.TrimSpace(strings.TrimPrefix(string(out), bom))
	if s == "" {
		return model.OSUpdateReport{}, errors.New("empty PowerShell output")
	}
	if err := json.Unmarshal([]byte(s), &r); err != nil {
		if len(s) > 200 {
			s = s[:200]
		}
		return model.OSUpdateReport{}, fmt.Errorf("unexpected PowerShell output %q: %w", s, err)
	}
	rep := model.OSUpdateReport{SchemaVersion: 1, Status: "ok", Updates: []model.MissingUpdate{}}
	if r.Service != nil {
		rep.ServiceState = snake(r.Service.Status)
		rep.ServiceStartType = startType(r.Service.StartType, r.Service.Delayed != nil && *r.Service.Delayed == 1)
	}
	rep.Source, rep.SourceDetail = source(r)
	rep.RebootPending = (r.Reboot.WUA != nil && *r.Reboot.WUA) || r.Reboot.WUKey || r.Reboot.CBS
	rep.LastSearchSuccessAt = psTime(r.LastSearch)
	rep.LastInstallSuccessAt = psTime(r.LastInstall)
	switch {
	case r.SearchError != "":
		rep.Status = "failed"
		rep.Error = "Windows Update search failed"
		if r.SearchHResult != "" {
			rep.Error += " (" + r.SearchHResult + ")"
		}
		rep.Error += ": " + r.SearchError
	case r.ResultCode != nil && (*r.ResultCode == 4 || *r.ResultCode == 5):
		rep.Status = "failed"
		rep.Error = fmt.Sprintf("Windows Update search did not complete (result code %d)", *r.ResultCode)
	case r.ResultCode == nil:
		rep.Status = "failed"
		rep.Error = "Windows Update search returned no result"
	default:
		for _, u := range r.Updates {
			if m, ok := normalize(u); ok {
				rep.Updates = append(rep.Updates, m)
			}
		}
	}
	rep.Error = truncate(rep.Error, 1024)
	// Keep the most important ones if a machine is very far behind.
	slices.SortStableFunc(rep.Updates, func(a, b model.MissingUpdate) int { return rank(a) - rank(b) })
	if len(rep.Updates) > MaxUpdates {
		rep.Updates = rep.Updates[:MaxUpdates]
	}
	return rep, nil
}

func rank(u model.MissingUpdate) int {
	switch {
	case u.MsrcSeverity == "Critical":
		return 0
	case u.Classification == "security" || u.Classification == "critical" || u.MsrcSeverity != "":
		return 1
	}
	return 2
}

func normalize(u rawUpdate) (model.MissingUpdate, bool) {
	title := strings.TrimSpace(u.Title)
	if title == "" {
		return model.MissingUpdate{}, false
	}
	m := model.MissingUpdate{Title: truncate(title, 512), Classification: "other", KBIDs: []string{},
		CVEIDs: []string{}, Downloaded: u.Downloaded}
	if id := strings.ToLower(strings.TrimSpace(u.ID)); guidRe.MatchString(id) {
		m.UpdateID = id
	}
	for _, kb := range u.KB {
		if g := kbRe.FindStringSubmatch(strings.TrimSpace(kb)); g != nil && len(m.KBIDs) < 16 {
			if id := "KB" + g[1]; !slices.Contains(m.KBIDs, id) {
				m.KBIDs = append(m.KBIDs, id)
			}
		}
	}
	m.Classification = classify(u.Categories)
	if sev := strings.TrimSpace(u.Msrc); slices.Contains(msrcSeverities, sev) {
		m.MsrcSeverity = sev
	}
	if d := strings.TrimSpace(u.Date); dateRe.MatchString(d) {
		if _, err := time.Parse(time.DateOnly, d); err == nil && d >= "2000-01-01" {
			m.ReleaseDate = &d
		}
	}
	for _, c := range u.CVEs {
		c = strings.ToUpper(strings.TrimSpace(c))
		if cveRe.MatchString(c) && !slices.Contains(m.CVEIDs, c) && len(m.CVEIDs) < 500 {
			m.CVEIDs = append(m.CVEIDs, c)
		}
	}
	if u.Reboot != nil {
		m.RebootBehavior = map[int]string{0: "never", 1: "always", 2: "can_request"}[*u.Reboot]
	}
	if u.Size != nil && *u.Size > 0 && *u.Size < 1<<42 {
		n := int64(*u.Size)
		m.SizeBytes = &n
	}
	return m, true
}

func classify(cats []rawCategory) string {
	for _, c := range cats {
		if !strings.EqualFold(c.Type, "UpdateClassification") {
			continue
		}
		if v, ok := classificationIDs[strings.ToLower(strings.TrimSpace(c.ID))]; ok {
			return v
		}
		if v, ok := classificationNames[strings.ToLower(strings.TrimSpace(c.Name))]; ok {
			return v
		}
	}
	return "other"
}

// source decides where this machine gets its updates from: a WSUS server
// (policy UseWUServer=1 with WUServer), Windows Update for Business (deferral /
// target-version policies, Group Policy or MDM), or the default Automatic
// Updates service (Microsoft Update when the "other Microsoft products" opt-in
// is on, else Windows Update).
func source(r raw) (string, string) {
	wsus := r.Policy.UseWUServer != nil && *r.Policy.UseWUServer == 1 && strings.TrimSpace(r.Policy.WUServer) != ""
	var wufb []string
	for _, p := range r.Policy.WUfB {
		if p = strings.TrimSpace(p); p != "" {
			wufb = append(wufb, p)
		}
	}
	switch {
	case wsus:
		detail := strings.TrimSpace(r.Policy.WUServer)
		if len(wufb) > 0 {
			detail += " (Windows Update for Business policies also set)"
		}
		return "wsus", truncate(detail, 255)
	case len(wufb) > 0:
		return "wufb", truncate("policies: "+strings.Join(wufb, ", "), 255)
	}
	if r.DefaultService != nil {
		name := truncate(strings.TrimSpace(r.DefaultService.Name), 255)
		switch strings.ToLower(strings.TrimSpace(r.DefaultService.ID)) {
		case serviceMicrosoftUpdate:
			return "microsoft_update", name
		case serviceWindowsUpdate:
			return "windows_update", name
		case serviceWSUS:
			return "wsus", name
		}
		return "unknown", name
	}
	return "unknown", ""
}

// startType maps ServiceController.StartType (Automatic, Manual, Disabled, ...).
func startType(s string, delayed bool) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "automatic", "auto":
		if delayed {
			return "delayed_auto"
		}
		return "automatic"
	case "manual":
		return "manual"
	case "disabled":
		return "disabled"
	case "":
		return ""
	}
	return "unknown"
}

// snake turns "StartPending" into "start_pending".
func snake(s string) string {
	var b strings.Builder
	for i, r := range strings.TrimSpace(s) {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				b.WriteByte('_')
			}
			r += 'a' - 'A'
		}
		b.WriteRune(r)
	}
	out := stateRe.ReplaceAllString(b.String(), "")
	if len(out) > 24 {
		out = out[:24]
	}
	return out
}

func psTime(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || t.Year() < 2000 {
		return nil
	}
	t = t.UTC()
	return &t
}

func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n])
}

// Failed builds the report of a search that could not run at all (the
// script did not start, timed out or printed nothing usable).
func Failed(err error) model.OSUpdateReport {
	return model.OSUpdateReport{SchemaVersion: 1, Status: "failed", Source: "unknown",
		Error: truncate("Windows Update search failed: "+err.Error(), 1024), Updates: []model.MissingUpdate{}}
}
