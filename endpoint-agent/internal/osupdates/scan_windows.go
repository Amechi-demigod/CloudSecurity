//go:build windows

package osupdates

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"unicode/utf16"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/collect"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
)

// Supported reports whether this OS has a report.
const Supported = true

// psScan is fixed and read-only: it never downloads, installs or hides an
// update. The searcher keeps its defaults (ServerSelection = ssDefault,
// Online = true), which is what Windows itself uses: the configured WSUS
// server, or Windows Update / Microsoft Update for unmanaged and Windows Update
// for Business devices. Dates come from the API in UTC.
const psScan = `$ProgressPreference='SilentlyContinue'; [Console]::OutputEncoding=[Text.Encoding]::UTF8
$r=[ordered]@{}
try { $svc=Get-Service -Name wuauserv -ErrorAction Stop
 $r.service=[ordered]@{status=[string]$svc.Status; start_type=[string]$svc.StartType}
 try { $r.service.delayed=[int](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv' -ErrorAction Stop).DelayedAutostart } catch {} } catch { $r.service_error=$_.Exception.Message }
$pol=[ordered]@{wufb=@()}
$p='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$wufbNames='DeferQualityUpdates','DeferFeatureUpdates','DeferQualityUpdatesPeriodInDays','DeferFeatureUpdatesPeriodInDays','TargetReleaseVersion','ProductVersion','BranchReadinessLevel','PauseQualityUpdatesStartTime','PauseFeatureUpdatesStartTime'
try { $w=Get-ItemProperty -Path $p -ErrorAction Stop; $pol.wu_server=[string]$w.WUServer
 foreach ($n in $wufbNames) { if ($null -ne $w.$n) { $pol.wufb+="gpo:$n" } } } catch {}
try { $pol.use_wu_server=[int](Get-ItemProperty -Path "$p\AU" -ErrorAction Stop).UseWUServer } catch {}
try { $m=Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update' -ErrorAction Stop
 foreach ($n in $wufbNames) { if ($null -ne $m.$n) { $pol.wufb+="mdm:$n" } } } catch {}
$r.policy=$pol
try { foreach ($s in (New-Object -ComObject Microsoft.Update.ServiceManager).Services) { if ($s.IsDefaultAUService) { $r.default_service=[ordered]@{id=[string]$s.ServiceID; name=[string]$s.Name} } } } catch {}
$rb=[ordered]@{}
try { $rb.wua=[bool](New-Object -ComObject Microsoft.Update.SystemInfo).RebootRequired } catch {}
$rb.wu_key=[bool](Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
$rb.cbs=[bool](Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
$r.reboot=$rb
try { $res=(New-Object -ComObject Microsoft.Update.AutoUpdate).Results
 if ($res.LastSearchSuccessDate) { $r.last_search=[datetime]::SpecifyKind([datetime]$res.LastSearchSuccessDate,'Utc').ToString('o') }
 if ($res.LastInstallationSuccessDate) { $r.last_install=[datetime]::SpecifyKind([datetime]$res.LastInstallationSuccessDate,'Utc').ToString('o') } } catch {}
try { $sess=New-Object -ComObject Microsoft.Update.Session
 try { $sess.ClientApplicationID='CNAPP agent (read-only update report)' } catch {}
 $res=$sess.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
 $r.result_code=[int]$res.ResultCode
 $r.updates=@(foreach ($u in $res.Updates) { [ordered]@{
  id=[string]$u.Identity.UpdateID; kb=@($u.KBArticleIDs | ForEach-Object { [string]$_ }); title=[string]$u.Title
  categories=@($u.Categories | ForEach-Object { [ordered]@{id=[string]$_.CategoryID; name=[string]$_.Name; type=[string]$_.Type} })
  msrc=[string]$u.MsrcSeverity; date=$(if ($u.LastDeploymentChangeTime) { ([datetime]$u.LastDeploymentChangeTime).ToString('yyyy-MM-dd') } else { '' })
  cves=@($u.CveIDs | ForEach-Object { [string]$_ }); reboot=[int]$u.InstallationBehavior.RebootBehavior
  size=[double]$u.MaxDownloadSize; downloaded=[bool]$u.IsDownloaded } })
} catch { $r.search_error=$_.Exception.Message; try { $r.search_hresult='0x{0:X8}' -f $_.Exception.HResult } catch {} }
ConvertTo-Json -InputObject $r -Depth 6 -Compress`

func powershellPath() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
}

func encodePS(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, len(u)*2)
	for i, c := range u {
		b[2*i], b[2*i+1] = byte(c), byte(c>>8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// Scan runs one Windows Update search (bounded by Timeout).
func Scan(ctx context.Context) (model.OSUpdateReport, error) {
	out, err := collect.Run(ctx, Timeout, powershellPath(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
		"Bypass", "-EncodedCommand", encodePS(psScan))
	rep, perr := Parse(out)
	if perr != nil {
		if err != nil {
			return model.OSUpdateReport{}, err
		}
		return model.OSUpdateReport{}, perr
	}
	return rep, nil
}
