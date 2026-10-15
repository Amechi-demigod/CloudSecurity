package collect

import (
	"strings"
	"testing"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/plist"
)

func mac(t *testing.T, name string) string { return string(fixture(t, "macos", name)) }

func TestMacParsers(t *testing.T) {
	n, v, b := parseSwVers(mac(t, "sw_vers.txt"))
	if n != "macOS" || v != "15.1" || b != "24B83" {
		t.Errorf("sw_vers %q %q %q", n, v, b)
	}
	boot, err := parseBoottime(mac(t, "boottime.txt"))
	if err != nil || boot.Unix() != 1791822269 {
		t.Errorf("boottime %v %v", boot, err)
	}
	if _, err := parseBoottime("garbage"); err == nil {
		t.Error("boottime garbage")
	}
	io := parseIoreg(mac(t, "ioreg.txt"))
	if io["IOPlatformSerialNumber"] != "C02TESTSERIAL" || io["IOPlatformUUID"] != "00000000-1111-2222-3333-444444444444" ||
		io["model"] != "Mac14,2" || io["manufacturer"] != "Apple Inc." {
		t.Errorf("ioreg %v", io)
	}
	if got := parseGroupMembership(mac(t, "dscl_admin.txt")); strings.Join(got, ",") != "root,alice,it-admin" {
		t.Errorf("admins %v", got)
	}
	if got := parseWho(mac(t, "who.txt")); strings.Join(got, ",") != "alice,bob" {
		t.Errorf("who %v", got)
	}
	ver, inst, ok := parseXProtectVersion(mac(t, "xprotect_version.txt"))
	if !ok || ver != "5367" || !inst.Equal(time.Date(2026, 10, 14, 20, 21, 0, 0, time.UTC)) {
		t.Errorf("xprotect %v %v %v", ver, inst, ok)
	}
}

func TestMacPostureParsers(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"fv on", parseFileVault("FileVault is On.\n").Status, "pass"},
		{"fv off", parseFileVault("FileVault is Off.\n").Status, "fail"},
		{"fv progress", parseFileVault("Encryption in progress: Percent completed = 42\n").Status, "fail"},
		{"fv deferred", parseFileVault("FileVault is Off.\nDeferred enablement appears to be active for user 'alice'.\n").Status, "fail"},
		{"fv junk", parseFileVault("").Status, "unknown"},
		{"fw on", parseAppFirewall("Firewall is enabled. (State = 1)", "Firewall stealth mode is off").Status, "pass"},
		{"fw block all", parseAppFirewall("Firewall is blocking all non-essential incoming connections. (State = 2)", "").Status, "pass"},
		{"fw off", parseAppFirewall("Firewall is disabled. (State = 0)", "").Status, "fail"},
		{"fw junk", parseAppFirewall("", "").Status, "unknown"},
		{"gk on", parseGatekeeper("assessments enabled\n").Status, "pass"},
		{"gk off", parseGatekeeper("assessments disabled\n").Status, "fail"},
		{"sip on", parseSIP("System Integrity Protection status: enabled.\n").Status, "pass"},
		{"sip off", parseSIP("System Integrity Protection status: disabled.\n").Status, "fail"},
		{"sip custom", parseSIP("System Integrity Protection status: enabled (Custom Configuration).\n").Status, "fail"},
		{"lock immediate", parseScreenLock("2026-10-15 13:09:15.599 sysadminctl[5458:1871446] screenLock delay is immediate").Status, "pass"},
		{"lock 60", parseScreenLock("sysadminctl[1:2] screenLock delay is 60 seconds").Status, "pass"},
		{"lock 3600", parseScreenLock("sysadminctl[1:2] screenLock delay is 3600 seconds").Status, "fail"},
		{"lock off", parseScreenLock("sysadminctl[1:2] screenLock is off").Status, "fail"},
		{"lock junk", parseScreenLock("Usage: sysadminctl").Status, "unknown"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: got %q want %q", c.name, c.got, c.want)
		}
	}
	firewall := parseAppFirewall("Firewall is enabled. (State = 1)", "Firewall stealth mode is on")
	if firewall.Data["stealth_mode"] != true {
		t.Error("stealth mode")
	}
}

func TestSoftwareUpdatePlist(t *testing.T) {
	m, err := plist.DecodeDict(fixture(t, "macos", "SoftwareUpdate.plist"))
	if err != nil {
		t.Fatal(err)
	}
	c := softwareUpdateCheck(m, time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC))
	if c.Status != "fail" || c.Data["pending_count"] != 2 || c.Data["days_since_last_install"] != 14 {
		t.Fatalf("%+v", c)
	}
	titles := c.Data["pending_titles"].([]string)
	if titles[0] != "macOS Sequoia 15.1.1" || titles[1] != "Command Line Tools for Xcode 16.1" {
		t.Errorf("titles %v", titles)
	}
	m, _ = plist.DecodeDict(fixture(t, "macos", "SoftwareUpdate-none.plist"))
	if c := softwareUpdateCheck(m, time.Now()); c.Status != "pass" {
		t.Errorf("none: %+v", c)
	}
	if c := softwareUpdateCheck(map[string]any{}, time.Now()); c.Status != "unknown" {
		t.Errorf("empty: %+v", c)
	}
}

func TestAppInfoPlist(t *testing.T) {
	m, err := plist.DecodeDict(fixture(t, "macos", "Chrome-Info.plist"))
	if err != nil {
		t.Fatal(err)
	}
	sw, ok := appFromInfoPlist(m, "/Applications/Google Chrome.app")
	if !ok || sw.Name != "Google Chrome" || sw.Version != "130.0.6723.70" || sw.Identifier != "com.google.Chrome" || sw.Publisher != "google" {
		t.Errorf("%+v", sw)
	}
	sw, _ = appFromInfoPlist(map[string]any{}, "/Applications/Foo.app")
	if sw.Name != "Foo" {
		t.Errorf("fallback name %q", sw.Name)
	}
}

func TestScreenLockProfile(t *testing.T) {
	m, _ := plist.DecodeDict(fixture(t, "macos", "screensaver-profile.plist"))
	c, ok := screenLockFromProfile(m)
	if !ok || c.Status != "pass" {
		t.Errorf("%+v", c)
	}
	c, _ = screenLockFromProfile(map[string]any{"askForPassword": false})
	if c.Status != "fail" {
		t.Errorf("%+v", c)
	}
	if _, ok := screenLockFromProfile(map[string]any{}); ok {
		t.Error("no keys")
	}
}
