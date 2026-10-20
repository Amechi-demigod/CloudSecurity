package wipe

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
)

type fakeWMI struct {
	calls []string
	err   error
}

func (f *fakeWMI) Invoke(_ context.Context, method string) (string, error) {
	f.calls = append(f.calls, method)
	return "ReturnValue=0", f.err
}

func ptr(b bool) *bool { return &b }

func cmd(params map[string]any) model.Command {
	now := time.Now().UTC()
	return model.Command{ID: "c1", DeviceID: "dev", Type: "wipe_device", Params: params, Nonce: strings.Repeat("n", 32),
		IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
}

func deps(w *fakeWMI, acks *[]string) Deps {
	return Deps{GOOS: "windows", OptedIn: func() (bool, error) { return true, nil }, Hostname: func() string { return "LAPTOP-001" },
		Probe: func(context.Context) Readiness {
			r := Readiness{OptIn: true, Supported: true, WinREEnabled: ptr(true), MDMBridge: ptr(true),
				Methods: []string{"doWipeMethod", "doWipeProtectedMethod", "doWipePersistUserDataMethod"}}
			r.Finish()
			return r
		},
		Ack:  func(context.Context) error { *acks = append(*acks, "ack"); return nil },
		Exec: w}
}

func TestWipeHappyPathAcksBeforeInvoking(t *testing.T) {
	w := &fakeWMI{}
	var acks []string
	d := deps(w, &acks)
	d.Exec = execFunc(func(ctx context.Context, m string) (string, error) {
		if len(acks) != len(w.calls)+1 {
			t.Fatal("wipe invoked before the acknowledgement")
		}
		return w.Invoke(ctx, m)
	})
	o := Run(context.Background(), cmd(map[string]any{"mode": "protected", "hostname": "laptop-001"}), d)
	if o.Status != "succeeded" || len(w.calls) != 1 || w.calls[0] != "doWipeProtectedMethod" {
		t.Fatalf("%+v %v", o, w.calls)
	}
	o = Run(context.Background(), cmd(map[string]any{"mode": "standard", "hostname": "LAPTOP-001"}), d)
	if o.Status != "succeeded" || w.calls[1] != "doWipeMethod" {
		t.Fatalf("%+v %v", o, w.calls)
	}
}

type execFunc func(context.Context, string) (string, error)

func (f execFunc) Invoke(ctx context.Context, m string) (string, error) { return f(ctx, m) }

func TestWipeRefusals(t *testing.T) {
	ctx := context.Background()
	good := map[string]any{"mode": "protected", "hostname": "LAPTOP-001"}
	cases := []struct {
		name   string
		mut    func(*Deps, *model.Command)
		status string
		want   string
	}{
		{"macos", func(d *Deps, _ *model.Command) { d.GOOS = "darwin" }, "rejected", "only supported on Windows"},
		{"no opt-in", func(d *Deps, _ *model.Command) { d.OptedIn = func() (bool, error) { return false, nil } }, "rejected", "opt in"},
		{"opt-in unreadable", func(d *Deps, _ *model.Command) {
			d.OptedIn = func() (bool, error) { return false, errors.New("owned by uid 501") }
		}, "rejected", "uid 501"},
		{"other host", func(_ *Deps, c *model.Command) { c.Params["hostname"] = "OTHER" }, "rejected", "this device is"},
		{"bad mode", func(_ *Deps, c *model.Command) { c.Params["mode"] = "persist_user_data" }, "rejected", "mode"},
		{"long validity", func(_ *Deps, c *model.Command) { c.ExpiresAt = c.IssuedAt.Add(48 * time.Hour) }, "rejected", "validity"},
		{"no issued_at", func(_ *Deps, c *model.Command) { c.IssuedAt = time.Time{} }, "rejected", "issued_at"},
		{"winre off", func(d *Deps, _ *model.Command) {
			d.Probe = func(context.Context) Readiness { return Readiness{WinREEnabled: ptr(false)} }
		}, "failed", "Windows RE is disabled"},
		{"no class", func(d *Deps, _ *model.Command) {
			d.Probe = func(context.Context) Readiness { return Readiness{MDMBridge: ptr(false), Error: "Invalid namespace"} }
		}, "failed", "Invalid namespace"},
		{"ack refused", func(d *Deps, _ *model.Command) {
			d.Ack = func(context.Context) error { return errors.New("server returned 409") }
		}, "failed", "not wiping"},
	}
	for _, tc := range cases {
		w := &fakeWMI{}
		var acks []string
		d := deps(w, &acks)
		c := cmd(map[string]any{"mode": good["mode"], "hostname": good["hostname"]})
		tc.mut(&d, &c)
		o := Run(ctx, c, d)
		if o.Status != tc.status || !strings.Contains(o.Output, tc.want) || len(w.calls) != 0 {
			t.Errorf("%s: %+v calls=%v", tc.name, o, w.calls)
		}
	}
	// WMI failure is reported.
	w := &fakeWMI{err: errors.New("0x80041013")}
	var acks []string
	if o := Run(ctx, cmd(good), deps(w, &acks)); o.Status != "failed" || !strings.Contains(o.Output, "0x80041013") {
		t.Errorf("%+v", o)
	}
}

func TestParseReagentc(t *testing.T) {
	en := `Windows Recovery Environment (Windows RE) and system reset configuration
Information:

    Windows RE status:         Enabled
    Windows RE location:       \\?\GLOBALROOT\device\harddisk0\partition4\Recovery\WindowsRE
    Boot Configuration Data (BCD) identifier: 6a3c2f43-1b9c-11ef-9c2b-a3e1f0c9b1d2
`
	dis := `    Windows RE status:         Disabled
    Boot Configuration Data (BCD) identifier: 00000000-0000-0000-0000-000000000000`
	de := `    Status von Windows RE:     Aktiviert
    BCD-Bezeichner (Startkonfigurationsdaten): 6a3c2f43-1b9c-11ef-9c2b-a3e1f0c9b1d2`
	deOff := `    Status von Windows RE:     Deaktiviert
    BCD-Bezeichner (Startkonfigurationsdaten): 00000000-0000-0000-0000-000000000000`
	for in, want := range map[string]*bool{en: ptr(true), dis: ptr(false), de: ptr(true), deOff: ptr(false), "garbage": nil} {
		got := ParseReagentc(in)
		if (got == nil) != (want == nil) || (got != nil && *got != *want) {
			t.Errorf("%q: got %v want %v", in[:20], got, want)
		}
	}
}

func TestReadinessFinish(t *testing.T) {
	r := Readiness{OptIn: true, Supported: true, WinREEnabled: ptr(true), MDMBridge: ptr(true), Methods: []string{"doWipeProtectedMethod"}}
	r.Finish()
	if !r.Ready || !strings.Contains(r.Detail, "ready") {
		t.Fatalf("%+v", r)
	}
	r = Readiness{OptIn: false, Supported: true, WinREEnabled: ptr(false), MDMBridge: ptr(true), Methods: []string{"doWipeMethod"}}
	r.Finish()
	if r.Ready || !strings.Contains(r.Detail, "opted in") || !strings.Contains(r.Detail, "Windows RE is disabled") ||
		!strings.Contains(r.Detail, "doWipeProtectedMethod not available") {
		t.Fatalf("%+v", r)
	}
	r = Readiness{OptIn: true, Supported: true}
	r.Finish()
	if r.Ready || !strings.Contains(r.Detail, "unknown") {
		t.Fatalf("%+v", r)
	}
	if d := r.Data(); d["method"] != "doWipeProtectedMethod" || d["ready"] != false {
		t.Fatalf("%v", d)
	}
}
