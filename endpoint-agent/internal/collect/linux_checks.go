package collect

import (
	"bufio"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
)

// Linux posture checks (agent 1.7.0): pure decision functions over parsed
// facts, so each one is tested with fixtures from Ubuntu 22.04 / 24.04,
// Debian 12, Rocky 9, RHEL 8 and Amazon Linux 2023 (testdata/linux/).
//
// Every check is read-only. A check that cannot run is "unknown" with the
// reason, never a failed check-in. Each check carries "evidence": the exact
// lines or values it decided on, shown in the console.

// MaxPackageCacheAge is how old the package metadata may be before the
// pending-updates check reports "unknown": the agent never refreshes it.
const MaxPackageCacheAge = 7 * 24 * time.Hour

func ev(lines ...string) []string {
	out := []string{}
	for _, l := range lines {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

func capStrings(in []string, n int) []string {
	if in == nil {
		return []string{}
	}
	if len(in) > n {
		return in[:n]
	}
	return in
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// cloudName is "AWS" / "Azure" / "GCP" for a detected cloud VM, else "". Only
// these three get the "see cloud posture" treatment: the provider is read
// from DMI (no metadata-service calls).
func cloudName(provider string) string {
	switch provider {
	case "aws":
		return "AWS"
	case "azure":
		return "Azure"
	case "gcp":
		return "GCP"
	}
	return ""
}

// ---------------------------------------------------------------- security updates

// PatchFacts are the inputs of the security-updates check.
type PatchFacts struct {
	Family   string         // apt | dnf
	APT      *APTSimulation // apt: simulated dist-upgrade
	DNF      *DNFUpdateinfo // dnf: cache-only updateinfo
	CacheMod time.Time      // when the package metadata was last refreshed (zero: unknown)
	Now      time.Time
}

// SecurityUpdatesCheck: fails when any security update is pending; unknown
// when the package metadata the server already has is older than 7 days.
func SecurityUpdatesCheck(f PatchFacts) model.PostureCheck {
	data := map[string]any{"package_manager": f.Family}
	age := time.Duration(-1)
	if !f.CacheMod.IsZero() {
		age = f.Now.Sub(f.CacheMod)
		data["cache_age_hours"] = int(age.Hours())
		data["cache_refreshed_at"] = f.CacheMod.UTC().Format(time.RFC3339)
	}
	ageText := "package cache age unknown"
	if age >= 0 {
		ageText = "cache " + humanAge(age) + " old"
	}
	if age > MaxPackageCacheAge {
		data["evidence"] = ev(ageText)
		return model.Check(model.StatusUnknown, fmt.Sprintf(
			"The package cache is %s old, so pending updates cannot be judged. The agent never refreshes it: "+
				"run the package manager's refresh (apt update / dnf makecache) or enable its timer.", humanAge(age)), data)
	}
	switch {
	case f.APT != nil:
		data["pending_updates"], data["security_updates"], data["packages"] = f.APT.Pending, f.APT.Security, capStrings(f.APT.Packages, 50)
		if f.APT.Security == 0 {
			data["evidence"] = ev(fmt.Sprintf("%d updates pending, none from a security pocket", f.APT.Pending), ageText)
			return model.Check(model.StatusPass, "No security updates are pending.", data)
		}
		data["evidence"] = ev(fmt.Sprintf("%d from a security pocket", f.APT.Security), ageText)
		return model.Check(model.StatusFail, fmt.Sprintf("%s waiting%s.", plural(f.APT.Security, "security update is", "security updates are"),
			including(f.APT.Packages)), data)
	case f.DNF != nil:
		data["security_updates"], data["packages"], data["severities"] = f.DNF.Advisories, capStrings(f.DNF.Packages, 50), f.DNF.Severities
		if f.DNF.Advisories == 0 {
			data["evidence"] = ev("no security advisories apply", ageText)
			return model.Check(model.StatusPass, "No security updates are pending.", data)
		}
		sev := []string{}
		for _, k := range []string{"critical", "important", "moderate", "low"} {
			if n := f.DNF.Severities[k]; n > 0 {
				sev = append(sev, fmt.Sprintf("%d %s", n, k))
			}
		}
		data["evidence"] = ev(strings.Join(sev, ", "), ageText)
		return model.Check(model.StatusFail, fmt.Sprintf("%s waiting%s.", plural(f.DNF.Advisories, "security advisory is", "security advisories are"),
			including(f.DNF.Packages)), data)
	}
	return model.Unknown("no supported package manager (apt, dnf) was found", nil)
}

func including(pkgs []string) string {
	var names []string
	for _, p := range pkgs {
		for prefix, label := range map[string]string{"openssl": "openssl", "linux-image": "the kernel", "kernel": "the kernel",
			"sudo": "sudo", "glibc": "glibc", "libc6": "glibc", "openssh": "openssh", "systemd": "systemd"} {
			if strings.HasPrefix(p, prefix) && !slices.Contains(names, label) {
				names = append(names, label)
			}
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return ""
	}
	return ", including " + strings.Join(names[:min(len(names), 4)], ", ")
}

func humanAge(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h", int(d.Hours()))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}

// ---------------------------------------------------------------- reboot required

// RebootFacts are the inputs of the reboot-required check.
type RebootFacts struct {
	Family        string
	RebootFlag    bool     // Debian / Ubuntu: /var/run/reboot-required exists
	RebootPkgs    []string // /var/run/reboot-required.pkgs
	RunningKernel string   // uname -r
	NewestKernel  string   // dnf family: newest installed kernel (version-release.arch)
}

// RebootCheck: fails when an installed kernel or core library is not running yet.
func RebootCheck(f RebootFacts) model.PostureCheck {
	data := map[string]any{"running_kernel": f.RunningKernel}
	switch f.Family {
	case "apt":
		data["reboot_flag"] = f.RebootFlag
		if f.RebootFlag {
			data["packages"] = capStrings(f.RebootPkgs, 20)
			data["evidence"] = ev("/var/run/reboot-required present", "packages: "+strings.Join(capStrings(f.RebootPkgs, 5), ", "))
			return model.Check(model.StatusFail, "A restart is needed to finish installing updates"+
				map[bool]string{true: " (" + strings.Join(capStrings(f.RebootPkgs, 3), ", ") + ")", false: ""}[len(f.RebootPkgs) > 0]+".", data)
		}
		data["evidence"] = ev("no /var/run/reboot-required")
		return model.Check(model.StatusPass, "No restart is pending.", data)
	case "dnf":
		if f.NewestKernel == "" || f.RunningKernel == "" {
			return model.Unknown("could not compare the running kernel with the installed kernels", nil)
		}
		data["newest_installed_kernel"] = f.NewestKernel
		data["evidence"] = ev("running "+f.RunningKernel, "installed "+f.NewestKernel)
		if RPMVerCmp(f.NewestKernel, f.RunningKernel) > 0 {
			return model.Check(model.StatusFail, "A newer kernel is installed but not running.", data)
		}
		return model.Check(model.StatusPass, "The running kernel is the newest installed.", data)
	}
	return model.Unknown("no supported package manager (apt, dnf) was found", nil)
}

// ---------------------------------------------------------------- automatic updates

// AutoUpdateFacts are the inputs of the automatic-security-updates check.
type AutoUpdateFacts struct {
	Family       string
	UnitFiles    map[string]string // systemctl list-unit-files states
	Packages     map[string]bool   // installed package names
	APTPeriodic  string            // /etc/apt/apt.conf.d/20auto-upgrades (and friends), concatenated
	DNFAutomatic string            // /etc/dnf/automatic.conf
}

var aptUnattended = regexp.MustCompile(`(?m)^\s*APT::Periodic::Unattended-Upgrade\s+"?(\d+)"?\s*;`)
var aptUpdateList = regexp.MustCompile(`(?m)^\s*APT::Periodic::Update-Package-Lists\s+"?(\d+)"?\s*;`)
var dnfApply = regexp.MustCompile(`(?m)^\s*apply_updates\s*=\s*(\w+)`)
var dnfType = regexp.MustCompile(`(?m)^\s*upgrade_type\s*=\s*(\w+)`)

func enabled(state string) bool { return state == "enabled" || state == "enabled-runtime" }

// AutoUpdatesCheck: unattended-upgrades (apt) or dnf-automatic (dnf) must be
// installed and its timer enabled.
func AutoUpdatesCheck(f AutoUpdateFacts) model.PostureCheck {
	data := map[string]any{}
	switch f.Family {
	case "apt":
		inst := f.Packages["unattended-upgrades"]
		timer := f.UnitFiles["apt-daily-upgrade.timer"]
		um := aptUnattended.FindStringSubmatch(f.APTPeriodic)
		lists := aptUpdateList.FindStringSubmatch(f.APTPeriodic)
		periodic := um != nil && um[1] != "0"
		data["unattended_upgrades_installed"], data["apt_daily_upgrade_timer"] = inst, timer
		data["evidence"] = ev("unattended-upgrades "+map[bool]string{true: "installed", false: "not installed"}[inst],
			"apt-daily-upgrade.timer "+orDash(timer),
			map[bool]string{true: "APT::Periodic::Unattended-Upgrade \"" + um1(um) + "\"", false: "APT::Periodic::Unattended-Upgrade not set"}[um != nil])
		if inst && enabled(timer) && periodic && !(lists != nil && lists[1] == "0") {
			return model.Check(model.StatusPass, "unattended-upgrades is enabled for the security pocket.", data)
		}
		return model.Check(model.StatusFail, "Automatic security updates are not enabled (unattended-upgrades).", data)
	case "dnf":
		for _, u := range []string{"dnf-automatic-install.timer", "dnf5-automatic.timer", "dnf-automatic.timer"} {
			if !enabled(f.UnitFiles[u]) {
				continue
			}
			applies := u == "dnf-automatic-install.timer"
			if m := dnfApply.FindStringSubmatch(f.DNFAutomatic); m != nil {
				applies = applies || strings.EqualFold(m[1], "yes") || strings.EqualFold(m[1], "true") || m[1] == "1"
			}
			typ := ""
			if m := dnfType.FindStringSubmatch(f.DNFAutomatic); m != nil {
				typ = m[1]
			}
			data["timer"], data["upgrade_type"], data["applies_updates"] = u, typ, applies
			data["evidence"] = ev(u+" enabled", map[bool]string{true: "apply_updates = yes", false: "downloads / notifies only"}[applies],
				map[bool]string{true: "upgrade_type = " + typ, false: ""}[typ != ""])
			if applies {
				return model.Check(model.StatusPass, u+" is enabled and applies updates.", data)
			}
			return model.Check(model.StatusFail, u+" is enabled but only downloads or notifies: updates are not applied automatically.", data)
		}
		data["evidence"] = ev("no dnf-automatic timer is enabled")
		return model.Check(model.StatusFail, "Automatic security updates are not enabled (dnf-automatic).", data)
	}
	return model.Unknown("no supported package manager (apt, dnf) was found", nil)
}

func um1(m []string) string {
	if m == nil {
		return ""
	}
	return m[1]
}

func orDash(s string) string {
	if s == "" {
		return "not installed"
	}
	return s
}

// ---------------------------------------------------------------- firewall

// FirewallState is what one firewall engine reports.
type FirewallState struct {
	Engine         string // ufw | firewalld | nftables | iptables
	Active         bool
	DefaultInbound string // deny | accept | unknown
	Evidence       []string
}

var ufwDefault = regexp.MustCompile(`(?mi)^Default:\s*(\w+(?: \(\w+\))?)\s*\(incoming\)`)

// ParseUFWStatus parses `ufw status verbose`. ok=false when it is not ufw output.
func ParseUFWStatus(s string) (FirewallState, bool) {
	st := FirewallState{Engine: "ufw", DefaultInbound: "unknown"}
	if !strings.Contains(s, "Status:") {
		return st, false
	}
	st.Active = regexp.MustCompile(`(?mi)^Status:\s*active`).MatchString(s)
	st.Evidence = ev(map[bool]string{true: "ufw active", false: "ufw inactive"}[st.Active])
	if m := ufwDefault.FindStringSubmatch(s); m != nil {
		d := strings.ToLower(m[1])
		switch {
		case strings.HasPrefix(d, "deny"), strings.HasPrefix(d, "reject"):
			st.DefaultInbound = "deny"
		case strings.HasPrefix(d, "allow"):
			st.DefaultInbound = "accept"
		}
		st.Evidence = append(st.Evidence, "default "+d+" (incoming)")
	}
	return st, true
}

// ParseFirewalld builds the state from `firewall-cmd --state`, `--get-default-zone`
// and `--permanent`-less `--zone=Z --get-target` (target: default | ACCEPT | DROP | %%REJECT%%).
func ParseFirewalld(stateOut, zoneOut, targetOut string) FirewallState {
	st := FirewallState{Engine: "firewalld", DefaultInbound: "unknown"}
	st.Active = strings.TrimSpace(stateOut) == "running"
	if !st.Active {
		st.Evidence = ev("firewalld " + strings.TrimSpace(stateOut))
		return st
	}
	zone, target := strings.TrimSpace(zoneOut), strings.TrimSpace(targetOut)
	st.Evidence = ev("firewalld running", "zone "+zone, "target "+target)
	switch strings.ToUpper(target) {
	case "ACCEPT":
		st.DefaultInbound = "accept"
	case "DEFAULT", "DROP", "%%REJECT%%", "REJECT":
		st.DefaultInbound = "deny" // "default" rejects what no service / port allows
	}
	return st
}

var (
	nftHook   = regexp.MustCompile(`hook input priority \S+;(?: policy (\w+);)?`)
	iptPolicy = regexp.MustCompile(`(?m)^-P INPUT (\w+)`)
	iptCatch  = regexp.MustCompile(`(?m)^-A INPUT -j (DROP|REJECT)\b`)
)

// ParseNftRuleset inspects `nft list ruleset` for base chains on the input hook.
// ok=false when there is no input-hook chain (no nftables firewall).
func ParseNftRuleset(s string) (FirewallState, bool) {
	st := FirewallState{Engine: "nftables", DefaultInbound: "unknown"}
	lines := strings.Split(s, "\n")
	found, deny := false, false
	for i, l := range lines {
		m := nftHook.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		found = true
		pol := m[1]
		if pol == "" {
			pol = "accept"
		}
		if pol == "drop" {
			deny = true
		}
		// A chain that ends in an unconditional drop / reject denies by default as well.
		for j := i + 1; j < len(lines) && strings.TrimSpace(lines[j]) != "}"; j++ {
			t := strings.TrimSpace(lines[j])
			if t == "drop" || t == "reject" || strings.HasPrefix(t, "reject with") {
				deny = true
			}
		}
		st.Evidence = append(st.Evidence, "input hook policy "+pol)
	}
	if !found {
		return st, false
	}
	st.Active = true
	st.DefaultInbound = map[bool]string{true: "deny", false: "accept"}[deny]
	return st, true
}

// ParseIptablesS inspects `iptables -S`. ok=false when there is no INPUT chain output.
func ParseIptablesS(s string) (FirewallState, bool) {
	st := FirewallState{Engine: "iptables", DefaultInbound: "unknown"}
	m := iptPolicy.FindStringSubmatch(s)
	if m == nil {
		return st, false
	}
	rules := 0
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, "-A INPUT") {
			rules++
		}
	}
	st.Evidence = ev("INPUT policy "+m[1], fmt.Sprintf("%d INPUT rules", rules))
	switch {
	case m[1] == "DROP" || m[1] == "REJECT":
		st.Active, st.DefaultInbound = true, "deny"
	case iptCatch.MatchString(s):
		st.Active, st.DefaultInbound = true, "deny"
	case rules > 0:
		st.Active, st.DefaultInbound = true, "accept"
	}
	return st, true
}

// FirewallCheck picks the first active engine (ufw, firewalld, nftables,
// iptables). No active firewall, or an inbound default of accept, fails; on an
// AWS / Azure / GCP VM that is Info with a pointer to cloud posture.
func FirewallCheck(states []FirewallState, cloudProvider string) model.PostureCheck {
	data := map[string]any{}
	var chosen *FirewallState
	for i := range states {
		if states[i].Active {
			chosen = &states[i]
			break
		}
	}
	all := []string{}
	for _, s := range states {
		all = append(all, s.Evidence...)
	}
	fail := func(detail string) model.PostureCheck {
		if c := cloudName(cloudProvider); c != "" {
			data["cloud_provider"] = cloudProvider
			return model.Check(model.StatusInfo, detail+" This is an "+c+" VM: security groups / network rules normally filter "+
				"traffic there, and cloud posture checks them.", data)
		}
		return model.Check(model.StatusFail, detail, data)
	}
	if chosen == nil {
		data["evidence"] = ev(append(all, "no active host firewall found")...)
		return fail("No active host firewall (ufw, firewalld, nftables or iptables).")
	}
	data["engine"], data["default_inbound"] = chosen.Engine, chosen.DefaultInbound
	data["evidence"] = ev(append([]string{}, chosen.Evidence...)...)
	if chosen.DefaultInbound == "accept" {
		return fail(chosen.Engine + " is active but accepts inbound traffic by default.")
	}
	if chosen.DefaultInbound == "unknown" {
		return model.Check(model.StatusInfo, chosen.Engine+" is active; its default inbound policy could not be read.", data)
	}
	return model.Check(model.StatusPass, chosen.Engine+" is active and denies inbound traffic by default.", data)
}

// ---------------------------------------------------------------- disk encryption

// BlockMount is a mounted block-device filesystem and whether dm-crypt / LUKS is in its device chain.
type BlockMount struct {
	Mount     string `json:"mount"`
	FSType    string `json:"fstype"`
	Encrypted bool   `json:"encrypted"`
}

type lsblkDev struct {
	Name       string     `json:"name"`
	Type       string     `json:"type"`
	FSType     string     `json:"fstype"`
	Mountpoint string     `json:"mountpoint"`
	Children   []lsblkDev `json:"children"`
}

// ParseLsblkJSON parses `lsblk --json --output NAME,TYPE,FSTYPE,MOUNTPOINT`
// (a tree: a mount is encrypted when a dm-crypt ("crypt") device or a
// crypto_LUKS signature is above it).
func ParseLsblkJSON(s string) ([]BlockMount, error) {
	var doc struct {
		Devices []lsblkDev `json:"blockdevices"`
	}
	if err := json.Unmarshal([]byte(s), &doc); err != nil {
		return nil, fmt.Errorf("lsblk output is not JSON: %w", err)
	}
	var out []BlockMount
	var walk func(d lsblkDev, enc bool)
	walk = func(d lsblkDev, enc bool) {
		enc = enc || d.Type == "crypt" || d.FSType == "crypto_LUKS" || strings.HasPrefix(d.Type, "crypt")
		if d.Mountpoint != "" && d.Mountpoint != "[SWAP]" {
			out = append(out, BlockMount{Mount: d.Mountpoint, FSType: d.FSType, Encrypted: enc})
		}
		for _, c := range d.Children {
			walk(c, enc)
		}
	}
	for _, d := range doc.Devices {
		walk(d, false)
	}
	return out, nil
}

// DiskEncryptionCheck looks at the mounted data volumes (not /boot, /boot/efi).
func DiskEncryptionCheck(mounts []BlockMount, cloudProvider string) model.PostureCheck {
	var vols []BlockMount
	for _, m := range mounts {
		if m.Mount == "/boot" || strings.HasPrefix(m.Mount, "/boot/") {
			continue
		}
		vols = append(vols, m)
	}
	data := map[string]any{"volumes": vols}
	if len(vols) == 0 {
		return model.Unknown("no mounted block-device volume was found (lsblk lists none)", nil)
	}
	var plain, enc []string
	lines := []string{}
	for _, v := range vols {
		state := "no dm-crypt"
		if v.Encrypted {
			state = "dm-crypt / LUKS"
			enc = append(enc, v.Mount)
		} else {
			plain = append(plain, v.Mount)
		}
		lines = append(lines, fmt.Sprintf("%s %s · %s", v.Mount, v.FSType, state))
	}
	data["evidence"] = capStrings(lines, 20)
	if len(plain) == 0 {
		return model.Check(model.StatusPass, "All mounted data volumes are encrypted (dm-crypt / LUKS).", data)
	}
	if c := cloudName(cloudProvider); c != "" {
		data["cloud_provider"] = cloudProvider
		return model.Check(model.StatusInfo, "No LUKS volumes. This is an "+c+" VM: provider disk encryption is not visible "+
			"from inside the server and is checked by cloud posture.", data)
	}
	return model.Check(model.StatusFail, fmt.Sprintf("%s not encrypted: %s.", plural(len(plain), "data volume is", "data volumes are"),
		strings.Join(capStrings(plain, 6), ", ")), data)
}

// ---------------------------------------------------------------- SSH

// ParseSSHDConfig parses `sshd -T` (effective configuration, keys lower-case).
// A key listed more than once (e.g. several `port`) keeps its first value.
func ParseSSHDConfig(s string) map[string]string {
	out := map[string]string{}
	for _, l := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), " ")
		if !ok {
			continue
		}
		k = strings.ToLower(k)
		if _, dup := out[k]; !dup {
			out[k] = strings.ToLower(strings.TrimSpace(v))
		}
	}
	return out
}

// SSHRootLoginCheck: yes fails, no passes, prohibit-password (also the old
// name without-password) and forced-commands-only are Info.
func SSHRootLoginCheck(cfg map[string]string) model.PostureCheck {
	v, ok := cfg["permitrootlogin"]
	if !ok {
		return model.Unknown("sshd -T did not report permitrootlogin", nil)
	}
	data := map[string]any{"permitrootlogin": v, "evidence": ev("permitrootlogin " + v)}
	switch v {
	case "yes":
		return model.Check(model.StatusFail, "Root can log in over SSH with a password.", data)
	case "no":
		return model.Check(model.StatusPass, "Root cannot log in over SSH.", data)
	case "prohibit-password", "without-password":
		return model.Check(model.StatusInfo, "Root can log in with a key only.", data)
	case "forced-commands-only":
		return model.Check(model.StatusInfo, "Root can log in with a key only to run forced commands.", data)
	}
	return model.Check(model.StatusUnknown, "Unrecognised PermitRootLogin value "+v+".", data)
}

// SSHPasswordCheck: PasswordAuthentication or KbdInteractiveAuthentication
// (older sshd: ChallengeResponseAuthentication) set to yes fails.
func SSHPasswordCheck(cfg map[string]string) model.PostureCheck {
	pw, ok := cfg["passwordauthentication"]
	if !ok {
		return model.Unknown("sshd -T did not report passwordauthentication", nil)
	}
	kbdKey := "kbdinteractiveauthentication"
	kbd, hasKbd := cfg[kbdKey]
	if !hasKbd {
		kbdKey = "challengeresponseauthentication"
		kbd, hasKbd = cfg[kbdKey]
	}
	data := map[string]any{"passwordauthentication": pw}
	lines := ev("passwordauthentication " + pw)
	if hasKbd {
		data[kbdKey] = kbd
		lines = append(lines, kbdKey+" "+kbd)
	}
	data["evidence"] = lines
	if pw == "yes" || kbd == "yes" {
		return model.Check(model.StatusFail, "Password login is allowed, so SSH accounts can be brute-forced.", data)
	}
	return model.Check(model.StatusPass, "SSH password login is disabled (keys only).", data)
}

// ---------------------------------------------------------------- admin accounts

// PasswdEntry is one /etc/passwd line (no secrets live there).
type PasswdEntry struct {
	Name  string
	UID   int
	GID   int
	Shell string
}

// ParsePasswd parses /etc/passwd.
func ParsePasswd(s string) []PasswdEntry {
	var out []PasswdEntry
	for _, l := range strings.Split(s, "\n") {
		f := strings.Split(l, ":")
		if len(f) < 7 || f[0] == "" || strings.HasPrefix(f[0], "#") {
			continue
		}
		uid, err1 := strconv.Atoi(f[2])
		gid, err2 := strconv.Atoi(f[3])
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, PasswdEntry{Name: f[0], UID: uid, GID: gid, Shell: f[6]})
	}
	return out
}

// ParseShadowEmpty returns the accounts whose password field in /etc/shadow
// is empty (no password needed to log in). It looks at nothing but whether
// the field is empty: hashes are never kept, returned, logged or sent. A
// locked account ("!", "*", "!!") is not empty.
func ParseShadowEmpty(s string) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(s))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		name, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok || name == "" || strings.HasPrefix(name, "#") {
			continue
		}
		field, _, _ := strings.Cut(rest, ":")
		if field == "" {
			out = append(out, name)
		}
	}
	return out
}

// GroupEntry is one /etc/group line.
type GroupEntry struct {
	Name    string
	GID     int
	Members []string
}

// ParseGroup parses /etc/group.
func ParseGroup(s string) []GroupEntry {
	var out []GroupEntry
	for _, l := range strings.Split(s, "\n") {
		f := strings.Split(l, ":")
		if len(f) < 4 || f[0] == "" || strings.HasPrefix(f[0], "#") {
			continue
		}
		gid, err := strconv.Atoi(f[2])
		if err != nil {
			continue
		}
		g := GroupEntry{Name: f[0], GID: gid}
		for _, m := range strings.Split(f[3], ",") {
			if m = strings.TrimSpace(m); m != "" {
				g.Members = append(g.Members, m)
			}
		}
		out = append(out, g)
	}
	return out
}

// SudoRule is one sudoers privilege specification.
type SudoRule struct {
	Principal string // user name, %group, or ALL
	NoPasswd  bool
	Full      bool // may run ALL commands
}

// SudoersFile is the result of parsing one sudoers file.
type SudoersFile struct {
	Rules    []SudoRule
	Includes []string // #include / @include files
	Dirs     []string // #includedir / @includedir directories
	Aliases  map[string][]string
}

var (
	sudoRule  = regexp.MustCompile(`^([^=]+?)\s+([^\s=,]+)\s*=\s*(.*)$`)
	sudoAlias = regexp.MustCompile(`^User_Alias\s+(\w+)\s*=\s*(.*)$`)
	sudoAll   = regexp.MustCompile(`(^|[\s:)])ALL\s*($|,)`)
)

// ParseSudoers parses one sudoers file. Defaults, other aliases and netgroups
// are ignored; "User_Alias" is expanded.
func ParseSudoers(s string) SudoersFile {
	f := SudoersFile{Aliases: map[string][]string{}}
	s = strings.ReplaceAll(s, "\\\n", " ")
	for _, raw := range strings.Split(s, "\n") {
		l := strings.TrimSpace(raw)
		switch {
		case l == "":
			continue
		case strings.HasPrefix(l, "#includedir "), strings.HasPrefix(l, "@includedir "):
			f.Dirs = append(f.Dirs, strings.Trim(strings.Fields(l)[1], `"`))
			continue
		case strings.HasPrefix(l, "#include "), strings.HasPrefix(l, "@include "):
			f.Includes = append(f.Includes, strings.Trim(strings.Fields(l)[1], `"`))
			continue
		case strings.HasPrefix(l, "#"):
			continue
		}
		if i := strings.Index(l, " #"); i >= 0 {
			l = strings.TrimSpace(l[:i])
		}
		if m := sudoAlias.FindStringSubmatch(l); m != nil {
			for _, u := range strings.Split(m[2], ",") {
				if u = strings.TrimSpace(u); u != "" {
					f.Aliases[m[1]] = append(f.Aliases[m[1]], u)
				}
			}
			continue
		}
		first := strings.Fields(l)[0]
		if slices.Contains([]string{"Defaults", "Cmnd_Alias", "Host_Alias", "Runas_Alias", "Cmnd_Alias"}, first) ||
			strings.HasPrefix(first, "Defaults") {
			continue
		}
		m := sudoRule.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		rest := m[3]
		full := sudoAll.MatchString(rest)
		nopw := strings.Contains(rest, "NOPASSWD:")
		for _, u := range strings.Split(m[1], ",") {
			u = strings.TrimSpace(u)
			if u == "" || strings.HasPrefix(u, "!") || strings.HasPrefix(u, "+") {
				continue
			}
			f.Rules = append(f.Rules, SudoRule{Principal: u, NoPasswd: nopw, Full: full})
		}
	}
	// Expand User_Alias names used as principals.
	var rules []SudoRule
	for _, r := range f.Rules {
		if names, ok := f.Aliases[r.Principal]; ok {
			for _, n := range names {
				rules = append(rules, SudoRule{Principal: n, NoPasswd: r.NoPasswd, Full: r.Full})
			}
			continue
		}
		rules = append(rules, r)
	}
	f.Rules = rules
	return f
}

// AdminFacts are the inputs of the admin-accounts check.
type AdminFacts struct {
	Passwd        []PasswdEntry
	Groups        []GroupEntry
	EmptyPassword []string   // from ParseShadowEmpty
	Sudoers       []SudoRule // all sudoers files, includes resolved
	ShadowErr     string     // "" or why /etc/shadow could not be read
	SudoersErr    string
}

// AdminAccountsCheck: fails for a UID 0 account other than root and for an
// account with an empty password field (accounts whose shell is nologin /
// false cannot log in and are listed, not failed); the list of accounts that
// can use sudo is Info.
func AdminAccountsCheck(f AdminFacts) model.PostureCheck {
	if len(f.Passwd) == 0 {
		return model.Unknown("could not read /etc/passwd", nil)
	}
	shell := map[string]string{}
	for _, p := range f.Passwd {
		shell[p.Name] = p.Shell
	}
	canLogin := func(n string) bool {
		s := shell[n]
		return !(strings.HasSuffix(s, "/nologin") || strings.HasSuffix(s, "/false") || s == "")
	}
	admin := map[string]bool{}
	groupsFound := []string{}
	for _, g := range f.Groups {
		if g.Name == "sudo" || g.Name == "wheel" || g.Name == "admin" {
			groupsFound = append(groupsFound, g.Name)
			for _, m := range g.Members {
				admin[m] = true
			}
			for _, p := range f.Passwd { // primary group
				if p.GID == g.GID {
					admin[p.Name] = true
				}
			}
		}
	}
	nopasswd := map[string]bool{}
	for _, r := range f.Sudoers {
		var members []string
		switch {
		case r.Principal == "ALL":
			members = []string{"(everyone)"}
		case strings.HasPrefix(r.Principal, "%"):
			gname := strings.TrimPrefix(r.Principal, "%")
			for _, g := range f.Groups {
				if g.Name == gname {
					members = append(members, g.Members...)
					for _, p := range f.Passwd {
						if p.GID == g.GID {
							members = append(members, p.Name)
						}
					}
				}
			}
			if r.Full && !slices.Contains(groupsFound, gname) {
				groupsFound = append(groupsFound, gname)
			}
		default:
			members = []string{r.Principal}
		}
		for _, m := range members {
			if r.Full {
				admin[m] = true
			}
			if r.NoPasswd {
				nopasswd[m] = true
			}
		}
	}
	delete(admin, "root")
	delete(nopasswd, "root")
	var uid0, empty []string
	for _, p := range f.Passwd {
		if p.UID == 0 && p.Name != "root" {
			uid0 = append(uid0, p.Name)
		}
	}
	var emptyNoLogin []string
	for _, n := range f.EmptyPassword {
		if canLogin(n) {
			empty = append(empty, n)
		} else {
			emptyNoLogin = append(emptyNoLogin, n)
		}
	}
	sortedKeys := func(m map[string]bool) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	sudoUsers, nopw := sortedKeys(admin), sortedKeys(nopasswd)
	sort.Strings(uid0)
	sort.Strings(empty)
	data := map[string]any{
		"admin_accounts": capStrings(sudoUsers, 50), "admin_groups": groupsFound, "nopasswd": capStrings(nopw, 50),
		"extra_uid0": capStrings(uid0, 20), "empty_password": capStrings(empty, 20),
		"empty_password_no_login": capStrings(emptyNoLogin, 20),
	}
	notes := []string{}
	if f.ShadowErr != "" {
		notes = append(notes, "empty passwords not checked: "+f.ShadowErr)
		data["empty_password_checked"] = false
	} else {
		data["empty_password_checked"] = true
	}
	if f.SudoersErr != "" {
		notes = append(notes, "sudoers not fully read: "+f.SudoersErr)
	}
	lines := []string{}
	if len(sudoUsers) > 0 {
		lines = append(lines, "sudo: "+strings.Join(capStrings(sudoUsers, 8), ", "))
	}
	if len(nopw) > 0 {
		lines = append(lines, "NOPASSWD: "+strings.Join(capStrings(nopw, 8), ", "))
	}
	if len(uid0) > 0 {
		lines = append(lines, "UID 0: "+strings.Join(uid0, ", "))
	}
	if len(empty) > 0 {
		lines = append(lines, "empty password: "+strings.Join(empty, ", "))
	}
	data["evidence"] = append(lines, notes...)
	var problems []string
	if len(uid0) > 0 {
		problems = append(problems, plural(len(uid0), "extra UID 0 account", "extra UID 0 accounts")+" ("+strings.Join(capStrings(uid0, 3), ", ")+")")
	}
	if len(empty) > 0 {
		problems = append(problems, plural(len(empty), "account has", "accounts have")+" an empty password ("+strings.Join(capStrings(empty, 3), ", ")+")")
	}
	if len(problems) > 0 {
		return model.Check(model.StatusFail, strings.Join(problems, "; ")+".", data)
	}
	detail := plural(len(sudoUsers), "account can", "accounts can") + " use sudo"
	if len(nopw) > 0 {
		detail += fmt.Sprintf("; %d without a password", len(nopw))
	}
	return model.Check(model.StatusInfo, detail+". No extra UID 0 accounts.", data)
}

// ---------------------------------------------------------------- endpoint protection

// ProtectionProduct describes one endpoint protection product.
type ProtectionProduct struct {
	Name     string
	Packages []string // package names that mean "installed"
	Units    []string // systemd services that mean "running"
}

// ProtectionProducts: Defender for Endpoint, CrowdStrike, SentinelOne, Sophos, ClamAV.
var ProtectionProducts = []ProtectionProduct{
	{"Microsoft Defender for Endpoint", []string{"mdatp"}, []string{"mdatp.service"}},
	{"CrowdStrike Falcon", []string{"falcon-sensor"}, []string{"falcon-sensor.service"}},
	{"SentinelOne", []string{"sentinelagent", "sentinelone"}, []string{"sentinelone.service", "s1-agent.service"}},
	{"Sophos", []string{"sophos-spl", "sophos-spl-base", "sophos-av", "sav-protect"}, []string{"sophos-spl.service", "sav-protect.service", "sophos-spl-av.service"}},
	{"ClamAV", []string{"clamav-daemon", "clamd", "clamav", "clamav-server"}, []string{"clamav-daemon.service", "clamd.service", "clamd@scan.service"}},
}

// EndpointProtectionCheck: an installed and running product passes; installed
// but stopped, or nothing found, fails.
func EndpointProtectionCheck(units []SystemdUnit, pkgs map[string]bool) model.PostureCheck {
	var running, stopped []string
	for _, p := range ProtectionProducts {
		inst := slices.ContainsFunc(p.Packages, func(n string) bool { return pkgs[n] })
		known, active := unitState(units, p.Units...)
		switch {
		case active:
			running = append(running, p.Name)
		case inst || known:
			stopped = append(stopped, p.Name)
		}
	}
	data := map[string]any{"running": running, "installed_not_running": stopped}
	if len(running) > 0 {
		data["evidence"] = ev("running: " + strings.Join(running, ", "))
		return model.Check(model.StatusPass, strings.Join(running, ", ")+" is installed and running.", data)
	}
	if len(stopped) > 0 {
		data["evidence"] = ev("installed but not running: " + strings.Join(stopped, ", "))
		return model.Check(model.StatusFail, strings.Join(stopped, ", ")+" is installed but not running.", data)
	}
	data["evidence"] = ev("looked for Defender for Endpoint, CrowdStrike, SentinelOne, Sophos, ClamAV")
	return model.Check(model.StatusFail, "No endpoint protection (Defender for Endpoint, CrowdStrike, SentinelOne, Sophos or ClamAV) was found.", data)
}

// ---------------------------------------------------------------- SELinux / AppArmor

// MACFacts are the inputs of the SELinux / AppArmor check.
type MACFacts struct {
	SELinuxPresent bool   // /sys/fs/selinux exists
	SELinuxEnforce string // contents of /sys/fs/selinux/enforce
	AppArmorOn     string // /sys/module/apparmor/parameters/enabled
	AppArmorProfs  string // /sys/kernel/security/apparmor/profiles
}

// ParseAppArmorProfiles counts profiles by mode ("name (enforce)" lines).
func ParseAppArmorProfiles(s string) (enforce, complain int) {
	for _, l := range strings.Split(s, "\n") {
		switch {
		case strings.HasSuffix(strings.TrimSpace(l), "(enforce)"):
			enforce++
		case strings.HasSuffix(strings.TrimSpace(l), "(complain)"):
			complain++
		}
	}
	return
}

// MACCheck: SELinux enforcing, or AppArmor enabled with enforcing profiles, passes.
func MACCheck(f MACFacts) model.PostureCheck {
	data := map[string]any{}
	if f.SELinuxPresent {
		switch strings.TrimSpace(f.SELinuxEnforce) {
		case "1":
			data["selinux"] = "enforcing"
			data["evidence"] = ev("SELinux enforcing")
			return model.Check(model.StatusPass, "SELinux is enforcing.", data)
		case "0":
			data["selinux"] = "permissive"
			data["evidence"] = ev("SELinux permissive")
			return model.Check(model.StatusFail, "SELinux is loaded but in permissive mode (it logs, it does not block).", data)
		}
	}
	if strings.TrimSpace(f.AppArmorOn) == "Y" {
		enf, comp := ParseAppArmorProfiles(f.AppArmorProfs)
		data["apparmor"], data["profiles_enforcing"], data["profiles_complain"] = "enabled", enf, comp
		data["evidence"] = ev("AppArmor enabled", fmt.Sprintf("%d profiles enforcing, %d complain", enf, comp))
		if enf == 0 {
			return model.Check(model.StatusFail, "AppArmor is enabled but no profile is enforcing.", data)
		}
		return model.Check(model.StatusPass, fmt.Sprintf("AppArmor is enabled with %s.", plural(enf, "enforcing profile", "enforcing profiles")), data)
	}
	data["selinux"], data["apparmor"] = map[bool]string{true: "disabled", false: "absent"}[f.SELinuxPresent], "disabled"
	data["evidence"] = ev("no SELinux enforce flag", "AppArmor not enabled")
	return model.Check(model.StatusFail, "Neither SELinux nor AppArmor is enforcing.", data)
}

// ---------------------------------------------------------------- audit logging

// AuditCheck: auditd must be running.
func AuditCheck(units []SystemdUnit, pkgs map[string]bool) model.PostureCheck {
	known, active := unitState(units, "auditd.service")
	data := map[string]any{"installed": known || pkgs["auditd"] || pkgs["audit"]}
	switch {
	case active:
		data["evidence"] = ev("auditd.service active")
		return model.Check(model.StatusPass, "auditd is running.", data)
	case known:
		data["evidence"] = ev("auditd.service not active")
		return model.Check(model.StatusFail, "auditd is installed but not running.", data)
	}
	data["evidence"] = ev("auditd.service not found")
	return model.Check(model.StatusFail, "auditd is not installed.", data)
}

// ---------------------------------------------------------------- time sync

// ParseTimedatectlShow parses `timedatectl show` (KEY=value).
func ParseTimedatectlShow(s string) map[string]string {
	out := map[string]string{}
	for _, l := range strings.Split(s, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok {
			out[k] = v
		}
	}
	return out
}

// TimeSyncCheck: the system clock must be synchronised (chrony or
// systemd-timesyncd; read from the kernel's flag via timedatectl).
func TimeSyncCheck(td map[string]string, units []SystemdUnit) model.PostureCheck {
	_, chrony := unitState(units, "chronyd.service", "chrony.service")
	_, timesyncd := unitState(units, "systemd-timesyncd.service")
	_, ntpd := unitState(units, "ntpd.service", "ntp.service")
	svc := ""
	switch {
	case chrony:
		svc = "chrony"
	case timesyncd:
		svc = "systemd-timesyncd"
	case ntpd:
		svc = "ntpd"
	}
	data := map[string]any{"service": svc}
	sync, ok := td["NTPSynchronized"]
	if !ok {
		return model.Unknown("timedatectl did not report the synchronisation state", nil)
	}
	data["ntp_synchronized"] = sync
	data["evidence"] = ev("NTPSynchronized="+sync, "time service: "+map[bool]string{true: svc, false: "none running"}[svc != ""])
	if sync == "yes" {
		return model.Check(model.StatusPass, "The system clock is synchronised"+map[bool]string{true: " (" + svc + ")", false: ""}[svc != ""]+".", data)
	}
	if svc == "" {
		return model.Check(model.StatusFail, "The clock is not synchronised and no time service (chrony, systemd-timesyncd) is running.", data)
	}
	return model.Check(model.StatusFail, svc+" is running but the clock is not synchronised yet.", data)
}
