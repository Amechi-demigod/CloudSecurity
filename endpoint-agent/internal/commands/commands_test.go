package commands

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
)

var now = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

func cmd(t string, params map[string]any) model.Command {
	return model.Command{ID: "c1", DeviceID: "dev", Type: t, Params: params, Nonce: strings.Repeat("n", 32),
		ExpiresAt: now.Add(time.Hour)}
}

func TestAllowlist(t *testing.T) {
	for _, bad := range []string{"run_script", "shell", "exec", "wipe_device", "", "LOCK_DEVICE", "lock_device "} {
		if err := Validate(cmd(bad, nil), "dev", now); !errors.Is(err, ErrRejected) {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, ok := range []string{LockDevice, RecheckPosture, CollectLogs, RestartAgent} {
		if err := Validate(cmd(ok, nil), "dev", now); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
}

func TestValidateBindingExpiryParams(t *testing.T) {
	if err := Validate(cmd(LockDevice, nil), "other", now); err == nil {
		t.Error("device binding")
	}
	c := cmd(LockDevice, nil)
	c.ExpiresAt = now.Add(-time.Second)
	if err := Validate(c, "dev", now); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("expiry: %v", err)
	}
	c = cmd(LockDevice, nil)
	c.Nonce = "short"
	if err := Validate(c, "dev", now); err == nil {
		t.Error("nonce")
	}
	if err := Validate(cmd(RecheckPosture, map[string]any{"cmd": "whoami"}), "dev", now); err == nil {
		t.Error("unexpected param accepted")
	}
	for _, v := range []any{5.0, 100000.0, 600.5, "600", nil} {
		if err := Validate(cmd(UpdateCheckInInterval, map[string]any{"interval_seconds": v}), "dev", now); err == nil {
			t.Errorf("interval %v accepted", v)
		}
	}
	if err := Validate(cmd(UpdateCheckInInterval, map[string]any{"interval_seconds": 600.0}), "dev", now); err != nil {
		t.Error(err)
	}
}

func TestExecute(t *testing.T) {
	var interval int
	checkins := 0
	uploaded := 0
	d := Deps{
		CheckIn:     func(context.Context) error { checkins++; return nil },
		BuildLogs:   func(context.Context) ([]byte, error) { return []byte{0x1f, 0x8b, 1}, nil },
		UploadLogs:  func(_ context.Context, _ model.Command, gz []byte) error { uploaded = len(gz); return nil },
		SetInterval: func(s int) error { interval = s; return nil },
		Lock:        func(context.Context) (string, error) { return "", errors.New("no session") },
	}
	ctx := context.Background()
	if o := Execute(ctx, cmd(RecheckPosture, nil), d, nil); o.Status != "succeeded" || checkins != 1 {
		t.Errorf("%+v", o)
	}
	if o := Execute(ctx, cmd(CollectLogs, nil), d, nil); o.Status != "succeeded" || uploaded != 3 {
		t.Errorf("%+v", o)
	}
	if o := Execute(ctx, cmd(UpdateCheckInInterval, map[string]any{"interval_seconds": 1800.0}), d, nil); o.Status != "succeeded" || interval != 1800 {
		t.Errorf("%+v", o)
	}
	restarted := false
	o := Execute(ctx, cmd(RestartAgent, nil), d, func() { restarted = true })
	if o.Status != "succeeded" || o.After == nil || restarted {
		t.Errorf("%+v", o)
	}
	o.After()
	if !restarted {
		t.Error("restart not called")
	}
	if o := Execute(ctx, cmd(LockDevice, nil), d, nil); o.Status != "failed" || !strings.Contains(o.Output, "no session") {
		t.Errorf("%+v", o)
	}
	if o := Execute(ctx, cmd("run_script", nil), d, nil); o.Status != "rejected" {
		t.Errorf("%+v", o)
	}
}

func TestNewCommandValidation(t *testing.T) {
	ok := []model.Command{
		cmd(EnableLostMode, map[string]any{"message": "Lost laptop.\nPlease call.", "phone": "+234 (1) 234-5678"}),
		cmd(DisableLostMode, nil),
		cmd(WipeDevice, map[string]any{"mode": "protected", "hostname": "LAPTOP-1"}),
		cmd(RunScript, map[string]any{"bundle_id": strings.Repeat("a", 32), "bundle_version": "1.0.0",
			"script": "windows-list-local-admins", "script_sha256": strings.Repeat("b", 64), "parameters": map[string]any{}}),
	}
	ok[2].IssuedAt = now
	for _, c := range ok {
		if err := Validate(c, "dev", now); err != nil {
			t.Errorf("%s: %v", c.Type, err)
		}
	}
	bad := []model.Command{
		cmd(EnableLostMode, map[string]any{"message": "", "phone": "123456"}),
		cmd(EnableLostMode, map[string]any{"message": "hi", "phone": "call me"}),
		cmd(EnableLostMode, map[string]any{"message": "a\x07b", "phone": "123456"}),
		cmd(EnableLostMode, map[string]any{"message": strings.Repeat("x", 301), "phone": "123456"}),
		cmd(EnableLostMode, map[string]any{"message": "hi", "phone": "123456", "script": "x"}),
		cmd(DisableLostMode, map[string]any{"message": "x"}),
		cmd(WipeDevice, map[string]any{"mode": "persist_user_data", "hostname": "x"}),
		cmd(WipeDevice, map[string]any{"mode": "protected"}),
		cmd(RunScript, map[string]any{"bundle_id": "x", "bundle_version": "1", "script": "a", "script_sha256": "c"}),
		cmd(RunScript, map[string]any{"bundle_id": strings.Repeat("a", 32), "bundle_version": "1.0.0",
			"script": "x-y", "script_sha256": strings.Repeat("b", 64), "command": "whoami"}),
	}
	for i, c := range bad {
		if err := Validate(c, "dev", now); !errors.Is(err, ErrRejected) {
			t.Errorf("bad[%d] %s accepted", i, c.Type)
		}
	}
}

func TestExecuteNewCommands(t *testing.T) {
	var got []string
	d := Deps{
		LostMode: func(_ context.Context, enable bool, msg, phone string) (string, error) {
			got = append(got, fmt.Sprintf("%v|%s|%s", enable, msg, phone))
			return "ok", nil
		},
		Wipe: func(context.Context, model.Command) Outcome { return Outcome{Status: "succeeded", Output: "wiping"} },
		RunScript: func(context.Context, model.Command) Outcome {
			c := 0
			return Outcome{Status: "succeeded", ExitCode: &c}
		},
	}
	ctx := context.Background()
	if o := Execute(ctx, cmd(EnableLostMode, map[string]any{"message": " Lost ", "phone": "123456"}), d, nil); o.Status != "succeeded" {
		t.Errorf("%+v", o)
	}
	if o := Execute(ctx, cmd(DisableLostMode, nil), d, nil); o.Status != "succeeded" {
		t.Errorf("%+v", o)
	}
	if strings.Join(got, ",") != "true|Lost|123456,false||" {
		t.Errorf("%q", got)
	}
	if o := Execute(ctx, cmd(WipeDevice, nil), d, nil); o.Output != "wiping" {
		t.Errorf("%+v", o)
	}
	if o := Execute(ctx, cmd(RunScript, nil), d, nil); o.ExitCode == nil {
		t.Errorf("%+v", o)
	}
	if o := Execute(ctx, cmd(WipeDevice, nil), Deps{}, nil); o.Status != "rejected" {
		t.Errorf("%+v", o)
	}
}

func TestIsolateHostIncidentID(t *testing.T) {
	ok := []map[string]any{nil, {}, {"incident_id": "INC-4821"}, {"incident_id": "a"}, {"incident_id": strings.Repeat("a", 64)}}
	for _, p := range ok {
		if err := Validate(cmd(IsolateHost, p), "dev", now); err != nil {
			t.Errorf("%v: %v", p, err)
		}
	}
	bad := []map[string]any{
		{"incident_id": 123},                     // not a string
		{"incident_id": strings.Repeat("a", 65)}, // too long
		{"incident_id": "has space"},             // disallowed char
		{"incident_id": "line\nbreak"},           // control char / newline
		{"incident_id": "x", "other": "y"},       // unexpected extra param
	}
	for i, c := range bad {
		if err := Validate(cmd(IsolateHost, c), "dev", now); !errors.Is(err, ErrRejected) {
			t.Errorf("bad[%d] %v accepted", i, c)
		}
	}
	if err := Validate(cmd(IsolateHost, map[string]any{"incident_id": ""}), "dev", now); err != nil {
		t.Errorf("empty incident_id should be treated as absent: %v", err)
	}
	// restore_host still takes no parameters at all.
	if err := Validate(cmd(RestoreHost, nil), "dev", now); err != nil {
		t.Errorf("restore_host: %v", err)
	}
	if err := Validate(cmd(RestoreHost, map[string]any{"incident_id": "x"}), "dev", now); !errors.Is(err, ErrRejected) {
		t.Error("restore_host accepted a parameter")
	}
}

func TestExecuteIsolateRestoreHostNilDepRejects(t *testing.T) {
	ctx := context.Background()
	if o := Execute(ctx, cmd(IsolateHost, nil), Deps{}, nil); o.Status != "rejected" {
		t.Errorf("isolate_host nil dep: %+v", o)
	}
	if o := Execute(ctx, cmd(RestoreHost, nil), Deps{}, nil); o.Status != "rejected" {
		t.Errorf("restore_host nil dep: %+v", o)
	}
	var gotIsolate, gotRestore model.Command
	d := Deps{
		IsolateHost: func(_ context.Context, c model.Command) Outcome {
			gotIsolate = c
			return Outcome{Status: "succeeded", Output: "suspended"}
		},
		RestoreHost: func(_ context.Context, c model.Command) Outcome {
			gotRestore = c
			return Outcome{Status: "succeeded", Output: "restored"}
		},
	}
	c1 := cmd(IsolateHost, map[string]any{"incident_id": "INC-1"})
	if o := Execute(ctx, c1, d, nil); o.Status != "succeeded" || o.Output != "suspended" || gotIsolate.ID != c1.ID {
		t.Errorf("%+v", o)
	}
	c2 := cmd(RestoreHost, nil)
	if o := Execute(ctx, c2, d, nil); o.Status != "succeeded" || o.Output != "restored" || gotRestore.ID != c2.ID {
		t.Errorf("%+v", o)
	}
}

func TestCheckForUpdate(t *testing.T) {
	if err := Validate(cmd(CheckForUpdate, nil), "dev", now); err != nil {
		t.Fatalf("check_for_update rejected: %v", err)
	}
	// It takes no parameters: a server cannot smuggle a release, URL or binary in.
	for _, p := range []map[string]any{{"release_id": "x"}, {"url": "https://evil"}, {"version": "9.9.9"}} {
		if err := Validate(cmd(CheckForUpdate, p), "dev", now); !errors.Is(err, ErrRejected) {
			t.Errorf("params %v accepted", p)
		}
	}
	called := 0
	d := Deps{CheckForUpdate: func(context.Context) (string, error) { called++; return "update to 1.1.0 starts now", nil }}
	if out := Execute(context.Background(), cmd(CheckForUpdate, nil), d, nil); out.Status != "succeeded" || called != 1 ||
		out.Output != "update to 1.1.0 starts now" {
		t.Errorf("got %+v (called %d)", out, called)
	}
	d.CheckForUpdate = func(context.Context) (string, error) { return "", errors.New("self-update disabled") }
	if out := Execute(context.Background(), cmd(CheckForUpdate, nil), d, nil); out.Status != "failed" ||
		!strings.Contains(out.Output, "disabled") {
		t.Errorf("got %+v", out)
	}
	if out := Execute(context.Background(), cmd(CheckForUpdate, nil), Deps{}, nil); out.Status != "failed" {
		t.Errorf("nil dep: %+v", out)
	}
}
