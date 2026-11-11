//go:build linux

package collect

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestCollectSmokeLinux runs the real collector on the machine the tests run
// on (a CI container or runner, usually not root and often without systemd):
// every check must come back with a valid status and, when it could not run,
// a reason; nothing may panic or fail the whole report, and the report must
// stay within the server's schema limits.
func TestCollectSmokeLinux(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	r := Collect(ctx, Options{Software: true})
	if r.Device.OSFamily != "linux" || r.Device.OSName == "" || r.Device.Hostname == "" {
		t.Errorf("device %+v", r.Device)
	}
	for _, name := range []string{"security_updates", "reboot_required", "auto_updates", "firewall", "disk_encryption",
		"ssh_root_login", "ssh_password_login", "admin_accounts", "endpoint_protection", "mandatory_access_control",
		"audit_logging", "time_sync", "listening_ports", "package_inventory"} {
		c, ok := r.Posture[name]
		if !ok {
			t.Errorf("missing check %s", name)
			continue
		}
		switch c.Status {
		case "pass", "fail", "info":
		case "unknown":
			if c.Detail == "" {
				t.Errorf("%s: unknown without a reason", name)
			}
		default:
			t.Errorf("%s: status %q", name, c.Status)
		}
		if len(name) > 40 {
			t.Errorf("check name %s is longer than the server allows", name)
		}
	}
	if len(r.Posture) > 40 {
		t.Errorf("%d posture checks, the server accepts 40", len(r.Posture))
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "$6$") || strings.Contains(string(b), "$y$") {
		t.Error("a password hash must never appear in a report")
	}
	if c := r.Posture["package_inventory"]; c.Data["packages"] == nil {
		t.Errorf("package inventory %+v", c)
	}
	if c := r.Posture["listening_ports"]; len(b) > 0 && len(c.Detail) == 0 {
		t.Error("listening ports detail")
	}
}
