package collect

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
)

func lx(t *testing.T, parts ...string) string {
	t.Helper()
	return string(fixture(t, append([]string{"linux"}, parts...)...))
}

func status(t *testing.T, c model.PostureCheck, want string) {
	t.Helper()
	if c.Status != want {
		t.Fatalf("status %s, want %s (detail %q, data %v)", c.Status, want, c.Detail, c.Data)
	}
}

func TestOSReleaseAndEcosystem(t *testing.T) {
	cases := []struct{ dir, id, version, eco, family string }{
		{"ubuntu2204", "ubuntu", "22.04", "Ubuntu:22.04:LTS", "apt"},
		{"ubuntu2404", "ubuntu", "24.04", "Ubuntu:24.04:LTS", "apt"},
		{"debian12", "debian", "12", "Debian:12", "apt"},
		{"rocky9", "rocky", "9.4", "Rocky Linux:9", "dnf"},
		{"rhel8", "rhel", "8.10", "Red Hat", "dnf"},
		{"amzn2023", "amzn", "2023", "", "dnf"}, // OSV has no Amazon Linux feed
	}
	for _, c := range cases {
		osr := ParseOSRelease(lx(t, c.dir, "os-release"))
		if osr["ID"] != c.id || osr["VERSION_ID"] != c.version {
			t.Errorf("%s: %v", c.dir, osr)
		}
		if got := EcosystemFor(osr["ID"], osr["VERSION_ID"]); got != c.eco {
			t.Errorf("%s ecosystem %q, want %q", c.dir, got, c.eco)
		}
		if got := PackageFamily(osr); got != c.family {
			t.Errorf("%s family %q", c.dir, got)
		}
	}
	// Mirrors backend ecosystem_for.
	for in, want := range map[[2]string]string{
		{"ubuntu", "23.10"}: "Ubuntu:23.10", {"ubuntu", "20.04"}: "Ubuntu:20.04:LTS", {"debian", "11"}: "Debian:11",
		{"alpine", "3.20.1"}: "Alpine:v3.20", {"almalinux", "8.9"}: "AlmaLinux:8", {"debian", ""}: "", {"sles", "15"}: "",
	} {
		if got := EcosystemFor(in[0], in[1]); got != want {
			t.Errorf("EcosystemFor%v = %q, want %q", in, got, want)
		}
	}
}

func TestDpkgStatus(t *testing.T) {
	pkgs := ParseDpkgStatus(lx(t, "ubuntu2204", "dpkg_status"))
	by := map[string]LinuxPackage{}
	for _, p := range pkgs {
		by[p.Name] = p
	}
	if len(pkgs) != 5 || by["oldpkg"].Name != "" {
		t.Fatalf("packages %v", pkgs)
	}
	if p := by["libssl3"]; p.SourceName != "openssl" || p.SourceVersion != "3.0.2-0ubuntu1.15" {
		t.Errorf("libssl3 %+v", p)
	}
	if p := by["bash"]; p.Version != "5.1-6ubuntu1.1+b1" || p.SourceName != "bash" || p.SourceVersion != "5.1-6ubuntu1.1" {
		t.Errorf("bash (binNMU) %+v", p)
	}
	sw := SoftwareFromPackages(pkgs, "Ubuntu:22.04:LTS")
	for _, s := range sw {
		if s.Name == "bash" && (s.SourceVersion != "5.1-6ubuntu1.1" || s.Ecosystem != "Ubuntu:22.04:LTS" || s.Source != "dpkg") {
			t.Errorf("software %+v", s)
		}
		if s.Name == "openssl" && (s.SourceName != "" || s.SourceVersion != "") {
			t.Errorf("same-name package should omit source: %+v", s)
		}
	}
}

func TestRPMQuery(t *testing.T) {
	for dir, want := range map[string]int{"rocky9": 4, "rhel8": 4, "amzn2023": 4} {
		if got := ParseRPMQuery(lx(t, dir, "rpm_qa.txt")); len(got) != want {
			t.Errorf("%s: %d packages, want %d", dir, len(got), want)
		}
	}
	pkgs := ParseRPMQuery(lx(t, "rocky9", "rpm_qa.txt"))
	if p := pkgs[0]; p.Name != "openssl-libs" || p.Version != "1:3.0.7-27.el9" || p.SourceName != "openssl" {
		t.Errorf("epoch / source: %+v", p)
	}
	if p := pkgs[1]; p.Version != "5.1.8-9.el9" {
		t.Errorf("no epoch: %+v", p)
	}
	for _, p := range pkgs {
		if p.Name == "gpg-pubkey" {
			t.Error("gpg-pubkey must be skipped")
		}
	}
}

func TestSecurityUpdates(t *testing.T) {
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-6 * time.Hour)

	r := ParseAPTSimulation(lx(t, "ubuntu2204", "apt_simulate.txt"))
	if r.Pending != 6 || r.Security != 4 {
		t.Fatalf("ubuntu 22.04: %+v", r)
	}
	c := SecurityUpdatesCheck(PatchFacts{Family: "apt", APT: &r, CacheMod: fresh, Now: now})
	status(t, c, "fail")
	if !strings.Contains(c.Detail, "4 security updates") || !strings.Contains(c.Detail, "openssl") || !strings.Contains(c.Detail, "kernel") {
		t.Errorf("detail %q", c.Detail)
	}
	if c.Data["cache_age_hours"] != 6 {
		t.Errorf("cache age %v", c.Data["cache_age_hours"])
	}

	r = ParseAPTSimulation(lx(t, "ubuntu2404", "apt_simulate.txt"))
	if r.Pending != 1 || r.Security != 0 {
		t.Fatalf("ubuntu 24.04: %+v", r)
	}
	status(t, SecurityUpdatesCheck(PatchFacts{Family: "apt", APT: &r, CacheMod: fresh, Now: now}), "pass")

	r = ParseAPTSimulation(lx(t, "debian12", "apt_simulate.txt"))
	if r.Pending != 3 || r.Security != 2 || !slices.Contains(r.Packages, "libc6") {
		t.Fatalf("debian 12: %+v", r)
	}

	// Stale cache: unknown, with the reason, never a pass or a fail.
	c = SecurityUpdatesCheck(PatchFacts{Family: "apt", APT: &r, CacheMod: now.Add(-9 * 24 * time.Hour), Now: now})
	status(t, c, "unknown")
	if !strings.Contains(c.Detail, "never refreshes") {
		t.Errorf("detail %q", c.Detail)
	}

	for dir, adv := range map[string]int{"rocky9": 3, "rhel8": 1, "amzn2023": 2} {
		d := ParseDNFUpdateinfo(lx(t, dir, "dnf_updateinfo.txt"))
		if d.Advisories != adv {
			t.Errorf("%s: %d advisories, want %d (%+v)", dir, d.Advisories, adv, d)
		}
		status(t, SecurityUpdatesCheck(PatchFacts{Family: "dnf", DNF: &d, CacheMod: fresh, Now: now}), "fail")
	}
	d := ParseDNFUpdateinfo(lx(t, "rocky9", "dnf_updateinfo.txt"))
	if d.Severities["important"] != 1 || d.Severities["critical"] != 1 || d.Severities["moderate"] != 1 {
		t.Errorf("severities %v", d.Severities)
	}
	none := ParseDNFUpdateinfo(lx(t, "rocky9", "dnf_updateinfo_none.txt"))
	status(t, SecurityUpdatesCheck(PatchFacts{Family: "dnf", DNF: &none, CacheMod: fresh, Now: now}), "pass")
	// Cache age unknown is reported, not guessed.
	c = SecurityUpdatesCheck(PatchFacts{Family: "dnf", DNF: &none, Now: now})
	status(t, c, "pass")
	if _, ok := c.Data["cache_age_hours"]; ok {
		t.Error("cache age must be absent when unknown")
	}
}

func TestRPMVerCmpAndReboot(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"5.14.0-427.13.1.el9_4.x86_64", "5.14.0-427.20.1.el9_4.x86_64", -1},
		{"4.18.0-553.16.1.el8_10.x86_64", "4.18.0-553.el8_10.x86_64", 1},
		{"1.0", "1.0", 0}, {"1.0~rc1", "1.0", -1}, {"1.0a", "1.0", 1}, {"1.10", "1.9", 1}, {"1.0^git1", "1.0", 1},
		{"6.1.132-147.221.amzn2023.x86_64", "6.1.127-135.201.amzn2023.x86_64", 1},
	} {
		if got := RPMVerCmp(c.a, c.b); got != c.want {
			t.Errorf("RPMVerCmp(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
	newest := NewestKernelRPM("4.18.0-553.el8_10.x86_64\n4.18.0-553.16.1.el8_10.x86_64\npackage kernel is not installed\n")
	if newest != "4.18.0-553.16.1.el8_10.x86_64" {
		t.Errorf("newest %q", newest)
	}
	status(t, RebootCheck(RebootFacts{Family: "dnf", RunningKernel: "4.18.0-553.el8_10.x86_64", NewestKernel: newest}), "fail")
	status(t, RebootCheck(RebootFacts{Family: "dnf", RunningKernel: newest, NewestKernel: newest}), "pass")
	status(t, RebootCheck(RebootFacts{Family: "dnf", RunningKernel: "5.14"}), "unknown")
	c := RebootCheck(RebootFacts{Family: "apt", RebootFlag: true, RebootPkgs: []string{"linux-image-5.15.0-125-generic"}, RunningKernel: "5.15.0-119-generic"})
	status(t, c, "fail")
	status(t, RebootCheck(RebootFacts{Family: "apt"}), "pass")
}

func TestAutoUpdates(t *testing.T) {
	units := ParseListUnitFiles(lx(t, "systemd", "list-unit-files.txt"))
	deb := AutoUpdateFacts{Family: "apt", UnitFiles: units, Packages: map[string]bool{"unattended-upgrades": true},
		APTPeriodic: lx(t, "ubuntu2204", "auto-upgrades")}
	status(t, AutoUpdatesCheck(deb), "pass")
	deb.Packages = map[string]bool{}
	status(t, AutoUpdatesCheck(deb), "fail")
	deb.Packages["unattended-upgrades"], deb.APTPeriodic = true, `APT::Periodic::Unattended-Upgrade "0";`
	status(t, AutoUpdatesCheck(deb), "fail")

	// dnf-automatic.timer is enabled in the fixture: it only counts when apply_updates = yes.
	rpm := AutoUpdateFacts{Family: "dnf", UnitFiles: units, DNFAutomatic: lx(t, "rocky9", "automatic.conf")}
	status(t, AutoUpdatesCheck(rpm), "pass")
	rpm.DNFAutomatic = lx(t, "rocky9", "automatic_notify.conf")
	c := AutoUpdatesCheck(rpm)
	status(t, c, "fail")
	if !strings.Contains(c.Detail, "only downloads or notifies") {
		t.Errorf("detail %q", c.Detail)
	}
	rpm.UnitFiles = map[string]string{"dnf-automatic-install.timer": "disabled"}
	status(t, AutoUpdatesCheck(rpm), "fail")
}

func TestLinuxFirewall(t *testing.T) {
	ufw, ok := ParseUFWStatus(lx(t, "ubuntu2204", "ufw_status.txt"))
	if !ok || !ufw.Active || ufw.DefaultInbound != "deny" {
		t.Fatalf("ufw %+v", ufw)
	}
	status(t, FirewallCheck([]FirewallState{ufw}, ""), "pass")
	off, _ := ParseUFWStatus(lx(t, "ubuntu2204", "ufw_inactive.txt"))
	if off.Active {
		t.Error("inactive ufw")
	}
	if _, ok := ParseUFWStatus("garbage"); ok {
		t.Error("garbage is not ufw")
	}

	nft, ok := ParseNftRuleset(lx(t, "debian12", "nft_ruleset.txt"))
	if !ok || nft.DefaultInbound != "deny" {
		t.Fatalf("nft %+v", nft)
	}
	status(t, FirewallCheck([]FirewallState{off, nft}, ""), "pass")
	open, _ := ParseNftRuleset(lx(t, "debian12", "nft_accept.txt"))
	status(t, FirewallCheck([]FirewallState{open}, ""), "fail")
	if _, ok := ParseNftRuleset("table inet x {\n}\n"); ok {
		t.Error("no input hook")
	}

	fw := ParseFirewalld("running\n", "public\n", "default\n")
	status(t, FirewallCheck([]FirewallState{fw}, ""), "pass")
	status(t, FirewallCheck([]FirewallState{ParseFirewalld("running", "trusted", "ACCEPT")}, ""), "fail")
	status(t, FirewallCheck([]FirewallState{ParseFirewalld("not running", "", "")}, ""), "fail")

	ipt, ok := ParseIptablesS(lx(t, "rhel8", "iptables_S.txt"))
	if !ok || ipt.DefaultInbound != "deny" { // policy ACCEPT but a final catch-all REJECT
		t.Fatalf("iptables with catch-all reject %+v", ipt)
	}
	status(t, FirewallCheck([]FirewallState{ipt}, ""), "pass")
	bare, _ := ParseIptablesS(lx(t, "amzn2023", "iptables_S.txt"))
	if bare.Active {
		t.Errorf("empty iptables is not a firewall: %+v", bare)
	}

	// Decision 2: on AWS / Azure / GCP a missing firewall is Info, on-prem / unknown is Fail.
	for _, p := range []string{"aws", "azure", "gcp"} {
		c := FirewallCheck([]FirewallState{bare}, p)
		status(t, c, "info")
		if !strings.Contains(c.Detail, "cloud posture") {
			t.Errorf("%s detail %q", p, c.Detail)
		}
	}
	status(t, FirewallCheck(nil, "oci"), "fail")
	status(t, FirewallCheck(nil, ""), "fail")
	status(t, FirewallCheck([]FirewallState{ufw}, "aws"), "pass")
}

func TestLinuxDiskEncryption(t *testing.T) {
	m, err := ParseLsblkJSON(lx(t, "ubuntu2204", "lsblk_plain.json"))
	if err != nil || len(m) != 3 {
		t.Fatalf("%v %v", m, err)
	}
	c := DiskEncryptionCheck(m, "")
	status(t, c, "fail")
	if !strings.Contains(c.Detail, "/data") {
		t.Errorf("detail %q", c.Detail)
	}
	for _, p := range []string{"aws", "azure", "gcp"} {
		c := DiskEncryptionCheck(m, p)
		status(t, c, "info")
		if !strings.Contains(c.Detail, "cloud posture") {
			t.Errorf("detail %q", c.Detail)
		}
	}
	status(t, DiskEncryptionCheck(m, "oci"), "fail")

	// LUKS + LVM: / is encrypted, /boot and swap are not judged.
	m, _ = ParseLsblkJSON(lx(t, "ubuntu2404", "lsblk_luks.json"))
	status(t, DiskEncryptionCheck(m, ""), "pass")
	m, _ = ParseLsblkJSON(lx(t, "rocky9", "lsblk_mixed.json"))
	c = DiskEncryptionCheck(m, "")
	status(t, c, "fail")
	if !strings.Contains(c.Detail, "1 data volume is") || !strings.Contains(c.Detail, "/") {
		t.Errorf("detail %q", c.Detail)
	}
	status(t, DiskEncryptionCheck(nil, ""), "unknown")
	if _, err := ParseLsblkJSON("not json"); err == nil {
		t.Error("garbage lsblk")
	}
}

func TestLinuxSSH(t *testing.T) {
	want := map[string][2]string{ // dir -> root, password
		"ubuntu2204": {"info", "fail"}, "ubuntu2404": {"info", "pass"}, "debian12": {"fail", "fail"},
		"rocky9": {"pass", "pass"}, "rhel8": {"info", "pass"}, "amzn2023": {"pass", "pass"},
	}
	for dir, w := range want {
		cfg := ParseSSHDConfig(lx(t, dir, "sshd_T.txt"))
		if got := SSHRootLoginCheck(cfg).Status; got != w[0] {
			t.Errorf("%s root login %s, want %s", dir, got, w[0])
		}
		if got := SSHPasswordCheck(cfg).Status; got != w[1] {
			t.Errorf("%s password login %s, want %s", dir, got, w[1])
		}
	}
	c := SSHPasswordCheck(ParseSSHDConfig(lx(t, "ubuntu2204", "sshd_T.txt")))
	ev, _ := c.Data["evidence"].([]string)
	if len(ev) != 2 || ev[0] != "passwordauthentication yes" || ev[1] != "kbdinteractiveauthentication no" {
		t.Errorf("evidence %v", ev)
	}
	// forced-commands-only is Info as well; unknown values and a missing key are not guessed.
	status(t, SSHRootLoginCheck(map[string]string{"permitrootlogin": "forced-commands-only"}), "info")
	status(t, SSHRootLoginCheck(map[string]string{}), "unknown")
	status(t, SSHPasswordCheck(map[string]string{}), "unknown")
}

func TestLinuxAdminAccounts(t *testing.T) {
	passwd := ParsePasswd(lx(t, "accounts", "passwd"))
	groups := ParseGroup(lx(t, "accounts", "group"))
	empty := ParseShadowEmpty(lx(t, "accounts", "shadow"))
	if !slices.Equal(empty, []string{"kiosk", "svc-backup"}) {
		t.Fatalf("empty password accounts %v", empty)
	}
	main := ParseSudoers(lx(t, "accounts", "sudoers"))
	if len(main.Dirs) != 1 || main.Dirs[0] != "/etc/sudoers.d" || len(main.Rules) != 3 {
		t.Fatalf("sudoers %+v", main)
	}
	d := ParseSudoers(lx(t, "accounts", "sudoers.d_90-deploy"))
	if len(d.Rules) != 2 || !d.Rules[0].NoPasswd || !d.Rules[0].Full || d.Rules[1].Full {
		t.Fatalf("sudoers.d %+v", d.Rules)
	}
	al := ParseSudoers(lx(t, "accounts", "sudoers_alias"))
	if len(al.Rules) != 3 || al.Rules[0].Principal != "deploy" || al.Rules[1].Principal != "j.okafor" || al.Rules[2].Principal != "ALL" || al.Rules[2].Full {
		t.Fatalf("alias expansion %+v", al.Rules)
	}

	f := AdminFacts{Passwd: passwd, Groups: groups, EmptyPassword: empty, Sudoers: append(main.Rules, d.Rules...)}
	c := AdminAccountsCheck(f)
	status(t, c, "fail") // toor has UID 0, kiosk has an empty password and a login shell
	if got := c.Data["extra_uid0"].([]string); !slices.Equal(got, []string{"toor"}) {
		t.Errorf("uid0 %v", got)
	}
	if got := c.Data["empty_password"].([]string); !slices.Equal(got, []string{"kiosk"}) {
		t.Errorf("empty password %v (svc-backup has nologin)", got)
	}
	if got := c.Data["empty_password_no_login"].([]string); !slices.Equal(got, []string{"svc-backup"}) {
		t.Errorf("no-login %v", got)
	}
	if got := c.Data["admin_accounts"].([]string); !slices.Equal(got, []string{"deploy", "j.okafor", "ops-admin"}) {
		t.Errorf("admins %v", got) // sudo group members + the ALL rule of sudoers.d
	}
	b, _ := json.Marshal(c)
	for _, secret := range []string{"fakesalt", "AAAAAAAA", "$6$", "$y$"} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("a password hash leaked into the check: %s", secret)
		}
	}

	// Only the list: without the two failing accounts the check is Info.
	var clean []PasswdEntry
	for _, p := range passwd {
		if p.Name != "toor" && p.Name != "kiosk" {
			clean = append(clean, p)
		}
	}
	f.Passwd, f.EmptyPassword = clean, nil
	c = AdminAccountsCheck(f)
	status(t, c, "info")
	if !strings.Contains(c.Detail, "No extra UID 0 accounts") {
		t.Errorf("detail %q", c.Detail)
	}
	status(t, AdminAccountsCheck(AdminFacts{}), "unknown")
}

func TestEndpointProtection(t *testing.T) {
	units := ParseListUnits(lx(t, "systemd", "list-units.txt"))
	c := EndpointProtectionCheck(units, map[string]bool{"mdatp": true})
	status(t, c, "pass")
	if !strings.Contains(c.Detail, "Defender for Endpoint") {
		t.Errorf("detail %q", c.Detail)
	}
	// ClamAV installed but its daemon is stopped.
	only := slices.DeleteFunc(slices.Clone(units), func(u SystemdUnit) bool { return u.Name == "mdatp.service" })
	c = EndpointProtectionCheck(only, map[string]bool{"clamav-daemon": true})
	status(t, c, "fail")
	if !strings.Contains(c.Detail, "installed but not running") {
		t.Errorf("detail %q", c.Detail)
	}
	status(t, EndpointProtectionCheck(nil, map[string]bool{}), "fail")
	status(t, EndpointProtectionCheck([]SystemdUnit{{Name: "falcon-sensor.service", Load: "loaded", Active: "active", Sub: "running"}}, nil), "pass")
}

func TestMACAuditTime(t *testing.T) {
	status(t, MACCheck(MACFacts{SELinuxPresent: true, SELinuxEnforce: "1\n"}), "pass")
	status(t, MACCheck(MACFacts{SELinuxPresent: true, SELinuxEnforce: "0"}), "fail")
	status(t, MACCheck(MACFacts{AppArmorOn: "Y\n", AppArmorProfs: lx(t, "proc", "apparmor_profiles")}), "pass")
	status(t, MACCheck(MACFacts{AppArmorOn: "Y", AppArmorProfs: "snap.x (complain)\n"}), "fail")
	status(t, MACCheck(MACFacts{}), "fail")
	enf, comp := ParseAppArmorProfiles(lx(t, "proc", "apparmor_profiles"))
	if enf != 2 || comp != 1 {
		t.Errorf("profiles %d %d", enf, comp)
	}

	units := ParseListUnits(lx(t, "systemd", "list-units.txt"))
	status(t, AuditCheck(units, nil), "pass")
	status(t, AuditCheck(nil, map[string]bool{}), "fail")
	status(t, AuditCheck([]SystemdUnit{{Name: "auditd.service", Load: "loaded", Active: "inactive"}}, nil), "fail")

	status(t, TimeSyncCheck(ParseTimedatectlShow(lx(t, "proc", "timedatectl_synced.txt")), units), "pass")
	c := TimeSyncCheck(ParseTimedatectlShow(lx(t, "proc", "timedatectl_unsynced.txt")), units)
	status(t, c, "fail")
	status(t, TimeSyncCheck(map[string]string{}, units), "unknown")
}

func TestServicesAndPorts(t *testing.T) {
	units := ParseListUnits(lx(t, "systemd", "list-units.txt"))
	svcs := ServicesFromSystemd(units, ParseListUnitFiles(lx(t, "systemd", "list-unit-files.txt")))
	by := map[string]model.Service{}
	for _, s := range svcs {
		by[s.Name] = s
	}
	if _, ok := by["foo.service"]; ok {
		t.Error("not-found units are not services")
	}
	if _, ok := by["getty@.service"]; ok {
		t.Error("templates are not services")
	}
	if s := by["nginx.service"]; s.Status != "running" || s.StartType != "auto" {
		t.Errorf("nginx %+v", s)
	}
	if s := by["broken.service"]; s.Status != "stopped" || s.StartType != "disabled" {
		t.Errorf("broken %+v", s)
	}
	if s := by["apt-daily.service"]; s.StartType != "manual" {
		t.Errorf("static unit %+v", s)
	}

	tcp := ParseProcNet(lx(t, "proc", "net_tcp"), "tcp")
	if len(tcp) != 2 || tcp[0].Port != 22 || tcp[0].Address != "0.0.0.0" || tcp[1].Address != "127.0.0.1" || tcp[1].Port != 3306 {
		t.Errorf("tcp %+v", tcp)
	}
	tcp6 := ParseProcNet(lx(t, "proc", "net_tcp6"), "tcp6")
	if len(tcp6) != 2 || tcp6[0].Port != 443 || tcp6[0].Address != "::" || tcp6[1].Address != "0:0:0:0:0:0:0:1" && tcp6[1].Port != 9090 {
		t.Errorf("tcp6 %+v", tcp6)
	}
}

func TestInventoryParsers(t *testing.T) {
	if n, ok := ParseMeminfoTotal(lx(t, "proc", "meminfo")); !ok || n != 8040680*1024 {
		t.Errorf("mem %d", n)
	}
	if name, cores := ParseCPUInfo(lx(t, "proc", "cpuinfo")); cores != 2 || !strings.Contains(name, "Xeon") {
		t.Errorf("cpu %q %d", name, cores)
	}
	if up, ok := ParseUptime("3540123.45 7000000.00\n"); !ok || up != 3540123 {
		t.Errorf("uptime %d", up)
	}
	m := ParseMounts(lx(t, "proc", "mounts"))
	if len(m) != 3 || m[2].Mount != "/mnt/my data" {
		t.Errorf("mounts %+v", m)
	}
	if got := ParseWho("deploy pts/0 2026-11-11 10:00 (10.0.0.5)\ndeploy pts/1 2026-11-11 10:05\nroot tty1 2026-11-10\n"); !slices.Equal(got, []string{"deploy", "root"}) {
		t.Errorf("who %v", got)
	}
}
