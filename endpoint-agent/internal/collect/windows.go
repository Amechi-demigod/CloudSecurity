package collect

// Windows parsers/evaluators. The collector (collect_windows.go) runs small,
// fixed PowerShell scripts that emit JSON; everything here is OS-independent
// and unit-tested against fixtures in testdata/windows/.

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
)

// decodePS decodes PowerShell ConvertTo-Json output (tolerating a UTF-8 BOM).
func decodePS(out []byte, v any) error {
	s := strings.TrimSpace(strings.TrimPrefix(string(out), "\ufeff"))
	if s == "" {
		return fmt.Errorf("empty PowerShell output")
	}
	if err := json.Unmarshal([]byte(s), v); err != nil {
		if len(s) > 200 {
			s = s[:200]
		}
		return fmt.Errorf("unexpected PowerShell output %q: %w", s, err)
	}
	return nil
}

// psList decodes a JSON list that Windows PowerShell 5.1 may also have emitted
// as a single bare element or as {"value": [...], "Count": n}.
type psList[T any] []T

func (l *psList[T]) UnmarshalJSON(b []byte) error {
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
		if err := json.Unmarshal(b, &wrapped); err == nil && wrapped.Value != nil {
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

// psTime parses ISO-8601 timestamps and the legacy "/Date(ms)/" form.
func psTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	if strings.HasPrefix(s, "/Date(") || strings.HasPrefix(s, "\\/Date(") {
		num := strings.TrimSuffix(strings.TrimSuffix(s[strings.Index(s, "(")+1:], "/"), ")")
		if i := strings.IndexAny(num, "+-"); i > 0 {
			num = num[:i]
		}
		ms, err := strconv.ParseInt(num, 10, 64)
		if err != nil {
			return time.Time{}, false
		}
		return time.UnixMilli(ms).UTC(), true
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.9999999", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// winSysInfo is the output of the sysinfo script.
type winSysInfo struct {
	Caption        string `json:"caption"`
	Version        string `json:"version"`
	Build          string `json:"build"`
	UBR            *int   `json:"ubr"`
	DisplayVersion string `json:"display_version"`
	OSArch         string `json:"os_arch"`
	LastBoot       string `json:"last_boot"`
	Manufacturer   string `json:"manufacturer"`
	Model          string `json:"model"`
	Memory         int64  `json:"memory"`
	Serial         string `json:"serial"`
	CPU            string `json:"cpu"`
	Cores          int    `json:"cores"`
	Disks          psList[struct {
		Mount      string `json:"mount"`
		Filesystem string `json:"filesystem"`
		Size       int64  `json:"size"`
		Free       int64  `json:"free"`
	}] `json:"disks"`
	Users       psList[string] `json:"users"`
	MachineGUID string         `json:"machine_guid"`
	Timezone    string         `json:"timezone"`
}

// applyWinSysInfo copies sysinfo into the device inventory.
func applyWinSysInfo(d *model.DeviceInfo, s winSysInfo, now time.Time) {
	d.OSName = strings.TrimSpace(s.Caption)
	if s.DisplayVersion != "" {
		d.OSName += " " + s.DisplayVersion
	}
	d.OSVersion = s.Version
	d.OSBuild = s.Build
	if s.UBR != nil {
		d.OSBuild = fmt.Sprintf("%s.%d", s.Build, *s.UBR)
	}
	d.Manufacturer, d.Model = strings.TrimSpace(s.Manufacturer), strings.TrimSpace(s.Model)
	d.SerialNumber = strings.TrimSpace(s.Serial)
	d.CPU = strings.TrimSpace(s.CPU)
	if s.Cores > 0 {
		d.CPUCores = iptr(s.Cores)
	}
	if s.Memory > 0 {
		d.MemoryBytes = i64(s.Memory)
	}
	if t, ok := psTime(s.LastBoot); ok {
		d.LastBoot = &t
		d.UptimeSeconds = i64(int64(now.Sub(t).Seconds()))
	}
	d.Disks = []model.Disk{}
	for _, k := range s.Disks {
		d.Disks = append(d.Disks, model.Disk{Mount: k.Mount, Filesystem: k.Filesystem, SizeBytes: i64(k.Size), FreeBytes: i64(k.Free)})
	}
	d.LoggedInUsers = []string{}
	for _, u := range s.Users {
		if u = strings.TrimSpace(u); u != "" && !slices.Contains(d.LoggedInUsers, u) {
			d.LoggedInUsers = append(d.LoggedInUsers, u)
		}
	}
	if s.Timezone != "" {
		d.Timezone = s.Timezone
	}
}

// winBitLocker is the output of the bitlocker script.
type winBitLocker struct {
	Source               string `json:"source"`
	Drive                string `json:"drive"`
	ProtectionStatus     *int   `json:"protection_status"`
	ConversionStatus     *int   `json:"conversion_status"`
	EncryptionPercentage *int   `json:"encryption_percentage"`
	EncryptionMethod     *int   `json:"encryption_method"`
	Error                string `json:"error"`
}

var conversionStatus = map[int]string{0: "fully decrypted", 1: "fully encrypted", 2: "encryption in progress",
	3: "decryption in progress", 4: "encryption paused", 5: "decryption paused"}

func evalBitLocker(b winBitLocker) model.PostureCheck {
	data := map[string]any{"drive": b.Drive}
	if b.ConversionStatus != nil {
		data["conversion_status"] = conversionStatus[*b.ConversionStatus]
	}
	if b.EncryptionPercentage != nil {
		data["encryption_percentage"] = *b.EncryptionPercentage
	}
	if b.ProtectionStatus == nil {
		c := model.Check(model.StatusUnknown, "BitLocker status unavailable on this system", data)
		if b.Error != "" {
			e := b.Error
			c.Error = &e
		}
		return c
	}
	switch *b.ProtectionStatus {
	case 1:
		return model.Check(model.StatusPass, fmt.Sprintf("BitLocker protection is on for %s", b.Drive), data)
	case 0:
		if b.ConversionStatus != nil && *b.ConversionStatus == 1 {
			return model.Check(model.StatusFail, fmt.Sprintf("BitLocker protection is suspended on %s", b.Drive), data)
		}
		if b.ConversionStatus != nil && *b.ConversionStatus == 2 {
			return model.Check(model.StatusFail, fmt.Sprintf("BitLocker encryption in progress on %s", b.Drive), data)
		}
		return model.Check(model.StatusFail, fmt.Sprintf("BitLocker is off for %s", b.Drive), data)
	}
	return model.Check(model.StatusUnknown, "BitLocker protection status unknown (volume may be locked)", data)
}

// winFirewallProfile is one Get-NetFirewallProfile row.
type winFirewallProfile struct {
	Name    string `json:"name"`
	Enabled string `json:"enabled"` // GpoBoolean: True | False | NotConfigured
}

func evalFirewall(profiles psList[winFirewallProfile]) model.PostureCheck {
	if len(profiles) == 0 {
		return model.Unknown("no firewall profiles returned", nil)
	}
	state := map[string]any{}
	var off []string
	for _, p := range profiles {
		on := strings.EqualFold(p.Enabled, "true") || p.Enabled == "1"
		state[strings.ToLower(p.Name)] = on
		if !on {
			off = append(off, p.Name)
		}
	}
	data := map[string]any{"profiles": state}
	if len(off) == 0 {
		return model.Check(model.StatusPass, "Windows Defender Firewall is on for all profiles", data)
	}
	return model.Check(model.StatusFail, "Firewall is off for: "+strings.Join(off, ", "), data)
}

// winAV is the output of the antivirus script.
type winAV struct {
	Defender *struct {
		AMServiceEnabled     *bool  `json:"am_service_enabled"`
		AntivirusEnabled     *bool  `json:"antivirus_enabled"`
		RealtimeEnabled      *bool  `json:"realtime_enabled"`
		SignatureAgeDays     *int   `json:"signature_age_days"`
		SignatureLastUpdated string `json:"signature_last_updated"`
		SignatureVersion     string `json:"signature_version"`
		TamperProtected      *bool  `json:"tamper_protected"`
		AMRunningMode        string `json:"am_running_mode"`
	} `json:"defender"`
	DefenderError string `json:"defender_error"`
	Products      psList[struct {
		Name  string `json:"name"`
		State int64  `json:"state"`
	}] `json:"products"`
	SecurityCenterError string `json:"security_center_error"`
}

// decodeProductState interprets the (undocumented but stable) Security Center
// productState bit field: 0x1000 = real-time scanning on, 0x10 = definitions out of date.
func decodeProductState(state int64) (enabled, upToDate bool) {
	return (state>>12)&0xF == 1, (state>>4)&0xF == 0
}

func isTrue(b *bool) bool { return b != nil && *b }

func evalAntivirus(a winAV) model.PostureCheck {
	data := map[string]any{}
	var products []map[string]any
	var activeThirdParty []string
	for _, p := range a.Products {
		on, fresh := decodeProductState(p.State)
		products = append(products, map[string]any{"name": p.Name, "enabled": on, "up_to_date": fresh})
		if on && !strings.Contains(strings.ToLower(p.Name), "windows defender") &&
			!strings.Contains(strings.ToLower(p.Name), "microsoft defender") {
			activeThirdParty = append(activeThirdParty, p.Name)
		}
	}
	if products != nil {
		data["products"] = products
	}
	if d := a.Defender; d != nil {
		data["defender_realtime_enabled"] = isTrue(d.RealtimeEnabled)
		data["defender_running_mode"] = d.AMRunningMode
		if d.SignatureVersion != "" {
			data["signature_version"] = d.SignatureVersion
		}
		if d.SignatureLastUpdated != "" {
			data["signature_last_updated"] = d.SignatureLastUpdated
		}
		if d.TamperProtected != nil {
			data["tamper_protected"] = *d.TamperProtected
		}
		if isTrue(d.AntivirusEnabled) && isTrue(d.RealtimeEnabled) && isTrue(d.AMServiceEnabled) {
			data["product"] = "Microsoft Defender Antivirus"
			if d.SignatureAgeDays != nil && *d.SignatureAgeDays < 10000 {
				data["signature_age_days"] = *d.SignatureAgeDays
			}
			return model.Check(model.StatusPass, "Microsoft Defender real-time protection is on", data)
		}
	}
	if len(activeThirdParty) > 0 {
		data["product"] = activeThirdParty[0]
		for _, p := range products {
			if p["name"] == activeThirdParty[0] && p["up_to_date"] == false {
				data["signature_age_days"] = 9999 // reported out of date by Security Center
			}
		}
		return model.Check(model.StatusPass, strings.Join(activeThirdParty, ", ")+" reported active by Windows Security Center", data)
	}
	if a.Defender != nil {
		return model.Check(model.StatusFail, "Microsoft Defender real-time protection is off and no other antivirus is active", data)
	}
	if len(products) > 0 {
		return model.Check(model.StatusFail, "No active antivirus product registered in Windows Security Center", data)
	}
	c := model.Check(model.StatusUnknown, "Antivirus status unavailable", data)
	msg := strings.TrimSpace(a.DefenderError + " " + a.SecurityCenterError)
	if msg != "" {
		c.Error = &msg
	}
	return c
}

// winPlatform is the output of the secure boot / TPM script.
type winPlatform struct {
	SecureBoot      *bool  `json:"secure_boot"`
	SecureBootError string `json:"secure_boot_error"`
	TPM             *struct {
		Present     *bool  `json:"present"`
		Ready       *bool  `json:"ready"`
		Enabled     *bool  `json:"enabled"`
		Activated   *bool  `json:"activated"`
		SpecVersion string `json:"spec_version"`
	} `json:"tpm"`
	TPMError string `json:"tpm_error"`
}

func evalSecureBoot(p winPlatform) model.PostureCheck {
	if p.SecureBoot == nil {
		c := model.Check(model.StatusUnknown, "Secure Boot state unavailable (legacy BIOS or unsupported platform)", nil)
		if p.SecureBootError != "" {
			e := p.SecureBootError
			c.Error = &e
		}
		return c
	}
	if *p.SecureBoot {
		return model.Check(model.StatusPass, "Secure Boot is on", nil)
	}
	return model.Check(model.StatusFail, "Secure Boot is off", nil)
}

func evalTPM(p winPlatform) model.PostureCheck {
	if p.TPM == nil || p.TPM.Present == nil {
		c := model.Check(model.StatusUnknown, "TPM state unavailable", nil)
		if p.TPMError != "" {
			e := p.TPMError
			c.Error = &e
		}
		return c
	}
	t := p.TPM
	data := map[string]any{"present": isTrue(t.Present), "ready": isTrue(t.Ready)}
	if t.SpecVersion != "" {
		data["spec_version"] = strings.TrimSpace(strings.SplitN(t.SpecVersion, ",", 2)[0])
	}
	if !isTrue(t.Present) {
		return model.Check(model.StatusFail, "No TPM present", data)
	}
	if !isTrue(t.Ready) {
		return model.Check(model.StatusFail, "TPM present but not ready", data)
	}
	return model.Check(model.StatusPass, "TPM present and ready", data)
}

// winUpdates is the output of the updates script.
type winUpdates struct {
	Pending        *int           `json:"pending"`
	PendingTitles  psList[string] `json:"pending_titles"`
	SearchError    string         `json:"search_error"`
	LastSearch     string         `json:"last_search"`
	LastInstall    string         `json:"last_install"`
	LastHotfix     string         `json:"last_hotfix"`
	RebootRequired bool           `json:"reboot_required"`
}

func evalUpdates(u winUpdates, now time.Time) model.PostureCheck {
	data := map[string]any{"reboot_required": u.RebootRequired}
	if len(u.PendingTitles) > 0 {
		t := u.PendingTitles
		if len(t) > 20 {
			t = t[:20]
		}
		data["pending_titles"] = t
	}
	if t, ok := psTime(u.LastSearch); ok {
		data["last_check"] = t.Format(time.RFC3339)
	}
	last, ok := psTime(u.LastInstall)
	if h, hok := psTime(u.LastHotfix); hok && (!ok || h.After(last)) {
		last, ok = h, true
	}
	if ok {
		data["last_install_date"] = last.Format(time.RFC3339)
		data["days_since_last_install"] = int(now.Sub(last).Hours() / 24)
	}
	if u.Pending == nil {
		c := model.Check(model.StatusUnknown, "Could not read pending updates from the Windows Update cache", data)
		if u.SearchError != "" {
			e := u.SearchError
			c.Error = &e
		}
		return c
	}
	data["pending_count"] = *u.Pending
	if *u.Pending > 0 {
		return model.Check(model.StatusFail, fmt.Sprintf("%d update(s) pending", *u.Pending), data)
	}
	if u.RebootRequired {
		return model.Check(model.StatusFail, "Updates installed; restart required", data)
	}
	return model.Check(model.StatusPass, "No pending updates", data)
}

// winAdmins is the output of the local-admins script.
type winAdmins struct {
	Group   string         `json:"group"`
	Members psList[string] `json:"members"`
}

// UserScreenSaver holds one loaded user hive's screen saver settings (REG_SZ values).
type UserScreenSaver struct {
	SID     string
	Active  string // ScreenSaveActive
	Secure  string // ScreenSaverIsSecure
	Timeout string // ScreenSaveTimeOut (seconds)
}

// MaxLockSeconds is the longest inactivity timeout that passes the screen-lock check.
const MaxLockSeconds = 900

// evalWindowsScreenLock: machine inactivity limit (policy) wins; otherwise
// every loaded interactive user hive must have a password-protected screen
// saver with a timeout <= 15 minutes. With neither configured the state is
// unknown (Windows may still require sign-in on wake from sleep).
func evalWindowsScreenLock(policySeconds *uint64, users []UserScreenSaver) model.PostureCheck {
	if policySeconds != nil && *policySeconds > 0 {
		data := map[string]any{"source": "InactivityTimeoutSecs policy", "timeout_seconds": *policySeconds}
		if *policySeconds <= MaxLockSeconds {
			return model.Check(model.StatusPass, fmt.Sprintf("Machine inactivity lock after %ds (policy)", *policySeconds), data)
		}
		return model.Check(model.StatusFail, fmt.Sprintf("Machine inactivity lock is %ds (> %ds)", *policySeconds, MaxLockSeconds), data)
	}
	if len(users) == 0 {
		return model.Check(model.StatusUnknown, "No inactivity lock policy and no signed-in user to inspect", nil)
	}
	var good, bad, unset []string
	for _, u := range users {
		if u.Active == "" && u.Secure == "" && u.Timeout == "" {
			unset = append(unset, u.SID)
			continue
		}
		t, err := strconv.Atoi(strings.TrimSpace(u.Timeout))
		if u.Active == "1" && u.Secure == "1" && err == nil && t > 0 && t <= MaxLockSeconds {
			good = append(good, u.SID)
		} else {
			bad = append(bad, u.SID)
		}
	}
	data := map[string]any{"users_compliant": len(good), "users_noncompliant": len(bad), "users_unset": len(unset)}
	switch {
	case len(bad) > 0:
		return model.Check(model.StatusFail, fmt.Sprintf("%d user(s) without a password-protected screen saver of <= %d s", len(bad), MaxLockSeconds), data)
	case len(unset) > 0 || len(good) == 0:
		return model.Check(model.StatusUnknown, "No inactivity lock policy or secure screen saver configured; Windows may still require sign-in on wake", data)
	}
	return model.Check(model.StatusPass, "Password-protected screen saver configured for all signed-in users", data)
}

// RawUninstallEntry is one registry Uninstall subkey.
type RawUninstallEntry struct {
	Key             string `json:"key"`
	DisplayName     string `json:"DisplayName"`
	DisplayVersion  string `json:"DisplayVersion"`
	Publisher       string `json:"Publisher"`
	InstallDate     string `json:"InstallDate"`
	SystemComponent uint64 `json:"SystemComponent"`
	ParentKeyName   string `json:"ParentKeyName"`
	ReleaseType     string `json:"ReleaseType"`
	Source          string `json:"source"`
}

// normalizeWindowsSoftware filters hidden components and updates and de-duplicates
// entries seen in both the 64- and 32-bit views (or per-user hives).
func normalizeWindowsSoftware(raw []RawUninstallEntry) []model.Software {
	out := []model.Software{}
	seen := map[string]bool{}
	for _, e := range raw {
		name := strings.TrimSpace(e.DisplayName)
		if name == "" || e.SystemComponent == 1 || e.ParentKeyName != "" {
			continue
		}
		switch strings.ToLower(e.ReleaseType) {
		case "update", "hotfix", "security update", "service pack":
			continue
		}
		ver := strings.TrimSpace(e.DisplayVersion)
		k := strings.ToLower(name) + "\x00" + ver
		if seen[k] {
			continue
		}
		seen[k] = true
		date := strings.TrimSpace(e.InstallDate)
		if len(date) == 8 { // yyyymmdd -> yyyy-mm-dd
			if _, err := strconv.Atoi(date); err == nil {
				date = date[:4] + "-" + date[4:6] + "-" + date[6:]
			}
		}
		out = append(out, model.Software{Name: name, Version: ver, Publisher: strings.TrimSpace(e.Publisher),
			Identifier: e.Key, InstallDate: date, Source: e.Source})
	}
	slices.SortFunc(out, func(a, b model.Software) int {
		return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})
	return out
}
