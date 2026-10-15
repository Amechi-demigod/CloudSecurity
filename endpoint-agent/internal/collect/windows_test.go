package collect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
)

func fixture(t *testing.T, parts ...string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{"..", "..", "testdata"}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func win[T any](t *testing.T, name string) T {
	t.Helper()
	var v T
	if err := decodePS(fixture(t, "windows", name), &v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return v
}

func wantStatus(t *testing.T, name string, c model.PostureCheck, status string) {
	t.Helper()
	if c.Status != status {
		t.Errorf("%s: status %q (%s), want %q", name, c.Status, c.Detail, status)
	}
}

var now = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

func TestWinSysInfo(t *testing.T) {
	var d model.DeviceInfo
	applyWinSysInfo(&d, win[winSysInfo](t, "sysinfo.json"), now)
	if d.OSName != "Microsoft Windows 11 Pro 23H2" || d.OSBuild != "22631.4317" || d.OSVersion != "10.0.22631" {
		t.Errorf("os: %q %q %q", d.OSName, d.OSBuild, d.OSVersion)
	}
	if d.SerialNumber != "PF4TEST1" || d.Manufacturer != "LENOVO" || *d.CPUCores != 10 || *d.MemoryBytes != 34089177088 {
		t.Errorf("hw: %+v", d)
	}
	if len(d.LoggedInUsers) != 1 || d.LoggedInUsers[0] != `CORP\alice` {
		t.Errorf("users (single value unwrapped by PowerShell): %v", d.LoggedInUsers)
	}
	if *d.UptimeSeconds != int64(now.Sub(time.Date(2026, 10, 15, 7, 12, 3, 500000000, time.UTC)).Seconds()) {
		t.Errorf("uptime %d", *d.UptimeSeconds)
	}
	if len(d.Disks) != 1 || *d.Disks[0].FreeBytes != 201234567168 {
		t.Errorf("disks %+v", d.Disks)
	}
}

func TestWinSysInfoPS51Quirks(t *testing.T) {
	var d model.DeviceInfo
	applyWinSysInfo(&d, win[winSysInfo](t, "sysinfo_ps51_wrapped.json"), now)
	if len(d.Disks) != 2 || d.LastBoot == nil || d.LastBoot.Unix() != 1791822269 || d.OSBuild != "20348" {
		t.Errorf("wrapped array / legacy date: %+v", d)
	}
}

func TestBitLocker(t *testing.T) {
	for name, want := range map[string]string{"bitlocker_on.json": "pass", "bitlocker_off.json": "fail",
		"bitlocker_suspended.json": "fail", "bitlocker_unavailable.json": "unknown"} {
		c := evalBitLocker(win[winBitLocker](t, name))
		wantStatus(t, name, c, want)
	}
	c := evalBitLocker(win[winBitLocker](t, "bitlocker_suspended.json"))
	if !strings.Contains(c.Detail, "suspended") {
		t.Errorf("detail %q", c.Detail)
	}
	if c := evalBitLocker(win[winBitLocker](t, "bitlocker_unavailable.json")); c.Error == nil {
		t.Error("unavailable should carry the error")
	}
}

func TestFirewall(t *testing.T) {
	wantStatus(t, "on", evalFirewall(win[psList[winFirewallProfile]](t, "firewall_on.json")), "pass")
	c := evalFirewall(win[psList[winFirewallProfile]](t, "firewall_public_off.json"))
	wantStatus(t, "public off", c, "fail")
	if !strings.Contains(c.Detail, "Public") {
		t.Errorf("detail %q", c.Detail)
	}
	wantStatus(t, "single", evalFirewall(win[psList[winFirewallProfile]](t, "firewall_single.json")), "pass")
	wantStatus(t, "empty", evalFirewall(nil), "unknown")
}

func TestAntivirus(t *testing.T) {
	c := evalAntivirus(win[winAV](t, "av_defender_on.json"))
	wantStatus(t, "defender on", c, "pass")
	if c.Data["signature_age_days"] != 0 || c.Data["product"] != "Microsoft Defender Antivirus" {
		t.Errorf("data %v", c.Data)
	}
	wantStatus(t, "defender off", evalAntivirus(win[winAV](t, "av_defender_off.json")), "fail")
	c = evalAntivirus(win[winAV](t, "av_thirdparty.json"))
	wantStatus(t, "third party", c, "pass")
	if c.Data["product"] != "CrowdStrike Falcon Sensor" {
		t.Errorf("product %v", c.Data["product"])
	}
	c = evalAntivirus(win[winAV](t, "av_server_stale.json"))
	wantStatus(t, "server", c, "pass")
	if c.Data["signature_age_days"] != 12 {
		t.Errorf("age %v", c.Data["signature_age_days"])
	}
	wantStatus(t, "nothing", evalAntivirus(winAV{DefenderError: "x"}), "unknown")
}

func TestProductState(t *testing.T) {
	cases := map[int64][2]bool{397568: {true, true}, 393472: {false, true}, 266240: {true, true}, 397584: {true, false}}
	for state, want := range cases {
		on, fresh := decodeProductState(state)
		if on != want[0] || fresh != want[1] {
			t.Errorf("%#x: got %v %v want %v", state, on, fresh, want)
		}
	}
}

func TestPlatform(t *testing.T) {
	p := win[winPlatform](t, "platform_ok.json")
	wantStatus(t, "secure boot", evalSecureBoot(p), "pass")
	c := evalTPM(p)
	wantStatus(t, "tpm", c, "pass")
	if c.Data["spec_version"] != "2.0" {
		t.Errorf("spec %v", c.Data["spec_version"])
	}
	vm := win[winPlatform](t, "platform_vm.json")
	wantStatus(t, "vm secure boot", evalSecureBoot(vm), "unknown")
	wantStatus(t, "vm tpm", evalTPM(vm), "unknown")
	off := false
	wantStatus(t, "sb off", evalSecureBoot(winPlatform{SecureBoot: &off}), "fail")
}

func TestUpdates(t *testing.T) {
	c := evalUpdates(win[winUpdates](t, "updates_pending.json"), now)
	wantStatus(t, "pending", c, "fail")
	if c.Data["pending_count"] != 2 || c.Data["days_since_last_install"] != 6 {
		t.Errorf("data %v", c.Data)
	}
	wantStatus(t, "reboot", evalUpdates(win[winUpdates](t, "updates_reboot.json"), now), "fail")
	c = evalUpdates(win[winUpdates](t, "updates_error.json"), now)
	wantStatus(t, "error", c, "unknown")
	if c.Error == nil || !strings.Contains(*c.Error, "8024402C") {
		t.Errorf("error %v", c.Error)
	}
	zero := 0
	wantStatus(t, "clean", evalUpdates(winUpdates{Pending: &zero}, now), "pass")
}

func TestAdmins(t *testing.T) {
	a := win[winAdmins](t, "admins.json")
	if len(a.Members) != 3 || a.Members[2] != `CORP\alice` {
		t.Errorf("%v", a.Members)
	}
	a = win[winAdmins](t, "admins_single.json")
	if len(a.Members) != 1 || a.Group != "Administrateurs" {
		t.Errorf("%v", a)
	}
}

func TestScreenLock(t *testing.T) {
	p600, p3600 := uint64(600), uint64(3600)
	wantStatus(t, "policy ok", evalWindowsScreenLock(&p600, nil), "pass")
	wantStatus(t, "policy long", evalWindowsScreenLock(&p3600, nil), "fail")
	wantStatus(t, "nobody", evalWindowsScreenLock(nil, nil), "unknown")
	good := UserScreenSaver{SID: "a", Active: "1", Secure: "1", Timeout: "600"}
	wantStatus(t, "user ok", evalWindowsScreenLock(nil, []UserScreenSaver{good}), "pass")
	insecure := UserScreenSaver{SID: "b", Active: "1", Secure: "0", Timeout: "600"}
	wantStatus(t, "insecure", evalWindowsScreenLock(nil, []UserScreenSaver{good, insecure}), "fail")
	unset := UserScreenSaver{SID: "c"}
	wantStatus(t, "unset", evalWindowsScreenLock(nil, []UserScreenSaver{unset}), "unknown")
}

func TestWindowsSoftware(t *testing.T) {
	sw := normalizeWindowsSoftware(win[[]RawUninstallEntry](t, "uninstall.json"))
	var names []string
	for _, s := range sw {
		names = append(names, s.Name)
	}
	if strings.Join(names, "|") != "7-Zip 24.08 (x64 edition)|Google Chrome|Zoom Workplace" {
		t.Fatalf("got %v", names)
	}
	if sw[0].InstallDate != "2026-09-01" || sw[0].Publisher != "Igor Pavlov" || sw[2].InstallDate != "bogus" {
		t.Errorf("%+v", sw)
	}
}

func TestPSTime(t *testing.T) {
	for _, s := range []string{"2026-10-15T03:10:00.0000000Z", "/Date(1791822269000)/", `\/Date(1791822269000+0000)\/`, "2026-10-15T03:10:00"} {
		if _, ok := psTime(s); !ok {
			t.Errorf("failed %q", s)
		}
	}
	if _, ok := psTime("yesterday"); ok {
		t.Error("parsed garbage")
	}
}

func TestDecodePSErrors(t *testing.T) {
	var v map[string]any
	if err := decodePS([]byte(""), &v); err == nil {
		t.Error("empty")
	}
	if err := decodePS([]byte("Get-Tpm : Access denied"), &v); err == nil {
		t.Error("garbage")
	}
}
