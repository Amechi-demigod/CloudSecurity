package commands

import (
	"context"
	"errors"
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
