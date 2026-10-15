//go:build windows

package collect

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows/registry"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
)

// Each script is fixed, read-only and emits one JSON document. They are passed
// with -EncodedCommand (no quoting issues, nothing user-controlled).
const psPrelude = `$ProgressPreference='SilentlyContinue'; [Console]::OutputEncoding=[Text.Encoding]::UTF8; `

const psSysInfo = `$ErrorActionPreference='Stop'
$cs=Get-CimInstance Win32_ComputerSystem; $os=Get-CimInstance Win32_OperatingSystem; $bios=Get-CimInstance Win32_BIOS
$cpu=@(Get-CimInstance Win32_Processor)
$cv=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$disks=@(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { [ordered]@{mount=$_.DeviceID; filesystem=$_.FileSystem; size=[int64]$_.Size; free=[int64]$_.FreeSpace} })
$users=@()
try { $users=@(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" | ForEach-Object { $o=Invoke-CimMethod -InputObject $_ -MethodName GetOwner; if ($o.User) { if ($o.Domain) { "$($o.Domain)\$($o.User)" } else { $o.User } } } | Sort-Object -Unique) } catch {}
if ($users.Count -eq 0 -and $cs.UserName) { $users=@($cs.UserName) }
$mg=''; try { $mg=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid } catch {}
$tz=''; try { $tz=(Get-TimeZone).Id } catch {}
[ordered]@{caption=$os.Caption; version=$os.Version; build=[string]$os.BuildNumber; ubr=$cv.UBR; display_version=[string]$cv.DisplayVersion;
 os_arch=$os.OSArchitecture; last_boot=$os.LastBootUpTime.ToUniversalTime().ToString('o'); manufacturer=$cs.Manufacturer; model=$cs.Model;
 memory=[int64]$cs.TotalPhysicalMemory; serial=$bios.SerialNumber; cpu=$cpu[0].Name; cores=[int](($cpu | Measure-Object NumberOfCores -Sum).Sum);
 disks=$disks; users=$users; machine_guid=$mg; timezone=$tz} | ConvertTo-Json -Depth 4 -Compress`

const psBitLocker = `$d=$env:SystemDrive
try {
 $v=Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -Filter "DriveLetter='$d'" -ErrorAction Stop
 if ($null -eq $v) { $r=[ordered]@{source='cim'; drive=$d; error='system volume not reported by Win32_EncryptableVolume'} }
 else {
  $r=[ordered]@{source='cim'; drive=$d; protection_status=[int]$v.ProtectionStatus; encryption_method=[int]$v.EncryptionMethod}
  try { $c=Invoke-CimMethod -InputObject $v -MethodName GetConversionStatus -ErrorAction Stop; $r.conversion_status=[int]$c.ConversionStatus; $r.encryption_percentage=[int]$c.EncryptionPercentage } catch {}
 }
} catch { $r=[ordered]@{source='none'; drive=$d; error=$_.Exception.Message} }
$r | ConvertTo-Json -Compress`

const psFirewall = `$ErrorActionPreference='Stop'
ConvertTo-Json -Compress -InputObject @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object { [ordered]@{name=[string]$_.Name; enabled=[string]$_.Enabled} })`

const psAntivirus = `$r=[ordered]@{}
try { $s=Get-MpComputerStatus -ErrorAction Stop
 $lu=$null; if ($s.AntivirusSignatureLastUpdated) { $lu=$s.AntivirusSignatureLastUpdated.ToUniversalTime().ToString('o') }
 $r.defender=[ordered]@{am_service_enabled=$s.AMServiceEnabled; antivirus_enabled=$s.AntivirusEnabled; realtime_enabled=$s.RealTimeProtectionEnabled;
  signature_age_days=[int]$s.AntivirusSignatureAge; signature_last_updated=$lu; signature_version=[string]$s.AntivirusSignatureVersion;
  tamper_protected=$s.IsTamperProtected; am_running_mode=[string]$s.AMRunningMode} } catch { $r.defender_error=$_.Exception.Message }
try { $r.products=@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | ForEach-Object { [ordered]@{name=[string]$_.displayName; state=[int64]$_.productState} }) } catch { $r.security_center_error=$_.Exception.Message }
$r | ConvertTo-Json -Depth 4 -Compress`

const psPlatform = `$r=[ordered]@{}
try { $r.secure_boot=[bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { $r.secure_boot_error=$_.Exception.Message }
try { $t=Get-Tpm -ErrorAction Stop; $r.tpm=[ordered]@{present=[bool]$t.TpmPresent; ready=[bool]$t.TpmReady; enabled=[bool]$t.TpmEnabled; activated=[bool]$t.TpmActivated}
 try { $w=Get-CimInstance -Namespace root/cimv2/Security/MicrosoftTpm -ClassName Win32_Tpm -ErrorAction Stop; $r.tpm.spec_version=[string]$w.SpecVersion } catch {} } catch { $r.tpm_error=$_.Exception.Message }
$r | ConvertTo-Json -Depth 4 -Compress`

// Windows Update: search the local cache only (Online=$false) so the check
// never blocks on a network scan; the OS refreshes the cache on its own schedule.
const psUpdates = `$r=[ordered]@{}
try { $au=New-Object -ComObject Microsoft.Update.AutoUpdate
 if ($au.Results.LastSearchSuccessDate) { $r.last_search=([datetime]$au.Results.LastSearchSuccessDate).ToUniversalTime().ToString('o') }
 if ($au.Results.LastInstallationSuccessDate) { $r.last_install=([datetime]$au.Results.LastInstallationSuccessDate).ToUniversalTime().ToString('o') } } catch {}
try { $s=(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher(); $s.Online=$false
 $res=$s.Search("IsInstalled=0 and IsHidden=0 and Type='Software'"); $r.pending=[int]$res.Updates.Count
 $r.pending_titles=@($res.Updates | Select-Object -First 20 | ForEach-Object { [string]$_.Title }) } catch { $r.search_error=$_.Exception.Message }
try { $h=Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn | Select-Object -Last 1; if ($h) { $r.last_hotfix=([datetime]$h.InstalledOn).ToUniversalTime().ToString('o') } } catch {}
$r.reboot_required=[bool](Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
$r | ConvertTo-Json -Depth 3 -Compress`

const psAdmins = `$sid='S-1-5-32-544'
$g=$null; try { $g=(Get-LocalGroup -SID $sid -ErrorAction Stop).Name } catch { $g=(New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1] }
try { $m=@(Get-LocalGroupMember -SID $sid -ErrorAction Stop | ForEach-Object { [string]$_.Name }) }
catch { $m=@(([ADSI]"WinNT://./$g,group").psbase.Invoke('Members') | ForEach-Object { $p=$_.GetType().InvokeMember('ADsPath','GetProperty',$null,$_,$null); (($p -replace '^WinNT://','') -replace '/','\') }) }
[ordered]@{group=$g; members=$m} | ConvertTo-Json -Compress`

func powershellPath() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
}

func encodePS(script string) string {
	u := utf16.Encode([]rune(psPrelude + script))
	b := make([]byte, len(u)*2)
	for i, c := range u {
		b[2*i], b[2*i+1] = byte(c), byte(c>>8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func ps(ctx context.Context, timeout time.Duration, script string, v any) error {
	out, err := Run(ctx, timeout, powershellPath(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-EncodedCommand", encodePS(script))
	if derr := decodePS(out, v); derr != nil {
		if err != nil {
			return err
		}
		return derr
	}
	return nil
}

func platformCollect(ctx context.Context, c collector, o Options) {
	d := &c.r.Device
	d.Architecture = nativeArch()
	c.guard("system", func() error {
		var s winSysInfo
		if err := ps(ctx, 90*time.Second, psSysInfo, &s); err != nil {
			return err
		}
		applyWinSysInfo(d, s, time.Now())
		return nil
	})
	c.posture("disk_encryption", func() (model.PostureCheck, error) {
		var b winBitLocker
		if err := ps(ctx, DefaultTimeout, psBitLocker, &b); err != nil {
			return model.PostureCheck{}, err
		}
		return evalBitLocker(b), nil
	})
	c.posture("firewall", func() (model.PostureCheck, error) {
		var p psList[winFirewallProfile]
		if err := ps(ctx, DefaultTimeout, psFirewall, &p); err != nil {
			return model.PostureCheck{}, err
		}
		return evalFirewall(p), nil
	})
	c.posture("antivirus", func() (model.PostureCheck, error) {
		var a winAV
		if err := ps(ctx, DefaultTimeout, psAntivirus, &a); err != nil {
			return model.PostureCheck{}, err
		}
		return evalAntivirus(a), nil
	})
	var plat winPlatform
	platErr := ps(ctx, DefaultTimeout, psPlatform, &plat)
	c.posture("secure_boot", func() (model.PostureCheck, error) {
		if platErr != nil {
			return model.PostureCheck{}, platErr
		}
		return evalSecureBoot(plat), nil
	})
	c.posture("tpm", func() (model.PostureCheck, error) {
		if platErr != nil {
			return model.PostureCheck{}, platErr
		}
		return evalTPM(plat), nil
	})
	c.posture("os_updates", func() (model.PostureCheck, error) {
		var u winUpdates
		if err := ps(ctx, 120*time.Second, psUpdates, &u); err != nil {
			return model.PostureCheck{}, err
		}
		return evalUpdates(u, time.Now()), nil
	})
	c.posture("screen_lock", func() (model.PostureCheck, error) {
		policy, users := screenSaverSettings()
		return evalWindowsScreenLock(policy, users), nil
	})
	c.posture("local_admins", func() (model.PostureCheck, error) {
		var a winAdmins
		if err := ps(ctx, DefaultTimeout, psAdmins, &a); err != nil {
			return model.PostureCheck{}, err
		}
		members := []string(a.Members)
		if members == nil {
			members = []string{}
		}
		return model.Check(model.StatusInfo, fmt.Sprintf("%d member(s) of %s", len(members), a.Group),
			map[string]any{"group": a.Group, "accounts": members}), nil
	})
	if o.Software {
		c.guard("software", func() error {
			c.r.Software = normalizeWindowsSoftware(uninstallEntries())
			return nil
		})
	}
}

func nativeArch() string {
	a := strings.ToLower(os.Getenv("PROCESSOR_ARCHITEW6432"))
	if a == "" {
		a = strings.ToLower(os.Getenv("PROCESSOR_ARCHITECTURE"))
	}
	switch a {
	case "amd64", "x86_64":
		return "amd64"
	case "arm64":
		return "arm64"
	case "x86":
		return "386"
	}
	return a
}

const uninstallPath = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`

func readUninstall(root registry.Key, path string, access uint32, source string) []RawUninstallEntry {
	k, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE|access)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}
	var out []RawUninstallEntry
	for _, n := range names {
		sk, err := registry.OpenKey(k, n, registry.QUERY_VALUE|access)
		if err != nil {
			continue
		}
		e := RawUninstallEntry{Key: n, Source: source}
		e.DisplayName, _, _ = sk.GetStringValue("DisplayName")
		e.DisplayVersion, _, _ = sk.GetStringValue("DisplayVersion")
		e.Publisher, _, _ = sk.GetStringValue("Publisher")
		e.InstallDate, _, _ = sk.GetStringValue("InstallDate")
		e.ParentKeyName, _, _ = sk.GetStringValue("ParentKeyName")
		e.ReleaseType, _, _ = sk.GetStringValue("ReleaseType")
		e.SystemComponent, _, _ = sk.GetIntegerValue("SystemComponent")
		sk.Close()
		out = append(out, e)
	}
	return out
}

func userSIDs() []string {
	k, err := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, _ := k.ReadSubKeyNames(-1)
	var sids []string
	for _, n := range names {
		if strings.HasPrefix(n, "S-1-5-21-") && !strings.HasSuffix(n, "_Classes") {
			sids = append(sids, n)
		}
	}
	return sids
}

func uninstallEntries() []RawUninstallEntry {
	var all []RawUninstallEntry
	all = append(all, readUninstall(registry.LOCAL_MACHINE, uninstallPath, registry.WOW64_64KEY, "registry_hklm64")...)
	all = append(all, readUninstall(registry.LOCAL_MACHINE, uninstallPath, registry.WOW64_32KEY, "registry_hklm32")...)
	for _, sid := range userSIDs() {
		all = append(all, readUninstall(registry.USERS, sid+`\`+uninstallPath, 0, "registry_user")...)
	}
	return all
}

func screenSaverSettings() (*uint64, []UserScreenSaver) {
	var policy *uint64
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
		registry.QUERY_VALUE|registry.WOW64_64KEY); err == nil {
		if v, _, err := k.GetIntegerValue("InactivityTimeoutSecs"); err == nil {
			policy = &v
		}
		k.Close()
	}
	var users []UserScreenSaver
	for _, sid := range userSIDs() {
		u := UserScreenSaver{SID: sid}
		for _, path := range []string{sid + `\Control Panel\Desktop`, sid + `\Software\Policies\Microsoft\Windows\Control Panel\Desktop`} {
			k, err := registry.OpenKey(registry.USERS, path, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			// The policy key (read second) overrides the user's own setting.
			if v, _, err := k.GetStringValue("ScreenSaveActive"); err == nil {
				u.Active = v
			}
			if v, _, err := k.GetStringValue("ScreenSaverIsSecure"); err == nil {
				u.Secure = v
			}
			if v, _, err := k.GetStringValue("ScreenSaveTimeOut"); err == nil {
				u.Timeout = v
			}
			k.Close()
		}
		users = append(users, u)
	}
	return policy, users
}

func rawMachineID(context.Context) (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", err
	}
	defer k.Close()
	v, _, err := k.GetStringValue("MachineGuid")
	if err == nil && v == "" {
		err = errors.New("empty MachineGuid")
	}
	return v, err
}
