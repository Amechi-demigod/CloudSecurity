package collect

// macOS output parsers. OS-independent so they are unit-tested everywhere
// against fixtures in testdata/macos/.

import (
	"bufio"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/plist"
)

// parseSwVers parses `sw_vers` ("ProductName:\tmacOS" lines).
func parseSwVers(out string) (name, ver, build string) {
	for _, l := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "ProductName":
			name = v
		case "ProductVersion":
			ver = v
		case "BuildVersion":
			build = v
		}
	}
	return
}

var bootRe = regexp.MustCompile(`sec\s*=\s*(\d+)`)

// parseBoottime parses `sysctl -n kern.boottime` ("{ sec = 1791822269, usec = 164489 } Mon Oct ...").
func parseBoottime(out string) (time.Time, error) {
	m := bootRe.FindStringSubmatch(out)
	if m == nil {
		return time.Time{}, fmt.Errorf("unexpected kern.boottime %q", strings.TrimSpace(out))
	}
	sec, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(sec, 0).UTC(), nil
}

var ioregRe = regexp.MustCompile(`"(IOPlatformSerialNumber|IOPlatformUUID|manufacturer|model)"\s*=\s*<?"([^"]*)"`)

// parseIoreg extracts serial, UUID, manufacturer and model from
// `ioreg -c IOPlatformExpertDevice -d 2`.
func parseIoreg(out string) map[string]string {
	res := map[string]string{}
	for _, m := range ioregRe.FindAllStringSubmatch(out, -1) {
		if _, seen := res[m[1]]; !seen {
			res[m[1]] = m[2]
		}
	}
	return res
}

// parseFileVault parses `fdesetup status`.
func parseFileVault(out string) model.PostureCheck {
	s := strings.TrimSpace(out)
	first := strings.SplitN(s, "\n", 2)[0]
	data := map[string]any{"output": first}
	switch {
	case strings.Contains(s, "FileVault is On"):
		return model.Check(model.StatusPass, "FileVault is on", data)
	case strings.Contains(s, "Encryption in progress"):
		return model.Check(model.StatusFail, "FileVault encryption in progress", data)
	case strings.Contains(s, "Decryption in progress"):
		return model.Check(model.StatusFail, "FileVault decryption in progress", data)
	case strings.Contains(s, "FileVault is Off"):
		return model.Check(model.StatusFail, "FileVault is off", data)
	}
	return model.Unknown("unrecognised fdesetup output", fmt.Errorf("%q", first))
}

// parseAppFirewall parses `socketfilterfw --getglobalstate` (+ --getstealthmode).
func parseAppFirewall(global, stealth string) model.PostureCheck {
	g := strings.ToLower(global)
	data := map[string]any{"stealth_mode": strings.Contains(strings.ToLower(stealth), "stealth mode is on")}
	switch {
	case strings.Contains(g, "firewall is enabled") || strings.Contains(g, "state = 1") || strings.Contains(g, "state = 2"):
		if strings.Contains(g, "state = 2") {
			data["block_all"] = true
		}
		return model.Check(model.StatusPass, "Application firewall is enabled", data)
	case strings.Contains(g, "firewall is disabled") || strings.Contains(g, "state = 0"):
		return model.Check(model.StatusFail, "Application firewall is disabled", data)
	}
	return model.Unknown("unrecognised socketfilterfw output", fmt.Errorf("%q", strings.TrimSpace(global)))
}

// parseGatekeeper parses `spctl --status`.
func parseGatekeeper(out string) model.PostureCheck {
	s := strings.TrimSpace(out)
	switch {
	case strings.Contains(s, "assessments enabled"):
		return model.Check(model.StatusPass, "Gatekeeper is enabled", nil)
	case strings.Contains(s, "assessments disabled"):
		return model.Check(model.StatusFail, "Gatekeeper is disabled", nil)
	}
	return model.Unknown("unrecognised spctl output", fmt.Errorf("%q", s))
}

// parseSIP parses `csrutil status`.
func parseSIP(out string) model.PostureCheck {
	s := strings.TrimSpace(out)
	l := strings.ToLower(s)
	switch {
	case strings.Contains(l, "status: enabled"):
		if strings.Contains(l, "custom configuration") {
			return model.Check(model.StatusFail, "SIP is enabled with a custom (weakened) configuration", map[string]any{"output": s})
		}
		return model.Check(model.StatusPass, "System Integrity Protection is enabled", nil)
	case strings.Contains(l, "status: disabled"):
		return model.Check(model.StatusFail, "System Integrity Protection is disabled", nil)
	}
	return model.Unknown("unrecognised csrutil output", fmt.Errorf("%q", s))
}

var screenLockDelayRe = regexp.MustCompile(`screenLock delay is (\d+) seconds?`)

// MaxScreenLockDelay is the longest password-after-sleep delay that still passes.
const MaxScreenLockDelay = 300

// parseScreenLock parses `sysadminctl -screenLock status` (printed on stderr).
func parseScreenLock(out string) model.PostureCheck {
	s := strings.TrimSpace(out)
	switch {
	case strings.Contains(s, "screenLock delay is immediate"):
		return model.Check(model.StatusPass, "Password required immediately after sleep or screen saver",
			map[string]any{"delay_seconds": 0})
	case strings.Contains(s, "screenLock is off"):
		return model.Check(model.StatusFail, "No password required after sleep or screen saver", nil)
	}
	if m := screenLockDelayRe.FindStringSubmatch(s); m != nil {
		d, _ := strconv.Atoi(m[1])
		data := map[string]any{"delay_seconds": d}
		if d <= MaxScreenLockDelay {
			return model.Check(model.StatusPass, fmt.Sprintf("Password required %ds after sleep or screen saver", d), data)
		}
		return model.Check(model.StatusFail, fmt.Sprintf("Password only required %ds after sleep or screen saver", d), data)
	}
	return model.Unknown("unrecognised sysadminctl output", fmt.Errorf("%q", s))
}

// screenLockFromProfile evaluates a managed com.apple.screensaver preference
// (configuration profile): askForPassword / askForPasswordDelay.
func screenLockFromProfile(m map[string]any) (model.PostureCheck, bool) {
	ask, ok := m["askForPassword"]
	if !ok {
		return model.PostureCheck{}, false
	}
	on := ask == true || ask == int64(1)
	delay, hasDelay := plist.Int(m, "askForPasswordDelay")
	data := map[string]any{"source": "configuration profile"}
	if hasDelay {
		data["delay_seconds"] = delay
	}
	if on && (!hasDelay || delay <= MaxScreenLockDelay) {
		return model.Check(model.StatusPass, "Screen lock enforced by configuration profile", data), true
	}
	return model.Check(model.StatusFail, "Configuration profile does not require a password promptly after sleep", data), true
}

// parseGroupMembership parses `dscl . -read /Groups/admin GroupMembership`.
func parseGroupMembership(out string) []string {
	users := []string{}
	for _, l := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "GroupMembership:"); ok {
			users = append(users, strings.Fields(v)...)
		}
	}
	return users
}

// parseWho returns unique user names from `who`.
func parseWho(out string) []string {
	users := []string{}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) > 0 && !slices.Contains(users, f[0]) {
			users = append(users, f[0])
		}
	}
	return users
}

var xprotectRe = regexp.MustCompile(`Version:\s*(\S+)\s+Installed:\s*(.+)`)

// parseXProtectVersion parses `xprotect version` (macOS 15+):
// "Version: 5367 Installed: 2026-10-14 20:21:00 +0000".
func parseXProtectVersion(out string) (ver string, installed time.Time, ok bool) {
	m := xprotectRe.FindStringSubmatch(out)
	if m == nil {
		return "", time.Time{}, false
	}
	t, err := time.Parse("2006-01-02 15:04:05 -0700", strings.TrimSpace(m[2]))
	if err != nil {
		return m[1], time.Time{}, true
	}
	return m[1], t.UTC(), true
}

// softwareUpdateCheck evaluates /Library/Preferences/com.apple.SoftwareUpdate.plist,
// the cache written by the system's own background update scans (so no slow or
// network-bound `softwareupdate --list` call is needed).
func softwareUpdateCheck(m map[string]any, now time.Time) model.PostureCheck {
	data := map[string]any{}
	titles := []string{}
	recs, hasRecs := m["RecommendedUpdates"].([]any)
	if hasRecs {
		for _, r := range recs {
			if d, ok := r.(map[string]any); ok {
				name := plist.String(d, "Display Name")
				if v := plist.String(d, "Display Version"); v != "" && !strings.Contains(name, v) {
					name += " " + v
				}
				titles = append(titles, name)
			}
		}
	}
	pending := -1
	if n, ok := plist.Int(m, "LastRecommendedUpdatesAvailable"); ok {
		pending = int(n)
	}
	if hasRecs && len(titles) > pending {
		pending = len(titles)
	}
	if len(titles) > 20 {
		titles = titles[:20]
	}
	data["pending_titles"] = titles
	if t, ok := plist.Time(m, "LastSuccessfulDate"); ok {
		data["last_check"] = t.UTC().Format(time.RFC3339)
	}
	var lastInstall time.Time
	if d, ok := m["InstallDateDictionary"].(map[string]any); ok {
		for _, v := range d {
			if t, ok := v.(time.Time); ok && t.After(lastInstall) {
				lastInstall = t
			}
		}
	}
	if !lastInstall.IsZero() {
		data["last_install_date"] = lastInstall.UTC().Format(time.RFC3339)
		data["days_since_last_install"] = int(now.Sub(lastInstall).Hours() / 24)
	}
	if pending < 0 {
		return model.Check(model.StatusUnknown, "No cached software update scan results", data)
	}
	data["pending_count"] = pending
	if pending == 0 {
		return model.Check(model.StatusPass, "No recommended updates pending", data)
	}
	return model.Check(model.StatusFail, fmt.Sprintf("%d recommended update(s) pending", pending), data)
}

// appFromInfoPlist turns an .app bundle's Info.plist into a Software entry.
func appFromInfoPlist(m map[string]any, appPath string) (model.Software, bool) {
	name := plist.String(m, "CFBundleDisplayName")
	if name == "" {
		name = plist.String(m, "CFBundleName")
	}
	if name == "" {
		name = strings.TrimSuffix(filepath.Base(appPath), ".app")
	}
	if name == "" {
		return model.Software{}, false
	}
	ver := plist.String(m, "CFBundleShortVersionString")
	if ver == "" {
		ver = plist.String(m, "CFBundleVersion")
	}
	return model.Software{Name: name, Version: ver, Identifier: plist.String(m, "CFBundleIdentifier"),
		Publisher: publisherFromBundleID(plist.String(m, "CFBundleIdentifier")), Source: "applications"}, true
}

// publisherFromBundleID gives a coarse vendor hint ("com.google.Chrome" -> "google").
func publisherFromBundleID(id string) string {
	parts := strings.Split(id, ".")
	if len(parts) >= 2 && (parts[0] == "com" || parts[0] == "org" || parts[0] == "net" || parts[0] == "io") {
		return parts[1]
	}
	return ""
}
