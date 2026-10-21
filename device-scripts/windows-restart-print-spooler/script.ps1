# Restarts the Print Spooler service and reports its state.
$ErrorActionPreference = 'Stop'
$svc = Get-Service -Name 'Spooler'
Write-Output "Before: $($svc.Status) (start type $($svc.StartType))"
if ($svc.StartType -eq 'Disabled') {
    Write-Output 'The Print Spooler service is disabled (for example by a PrintNightmare hardening policy); not starting it.'
    exit 2
}
Restart-Service -Name 'Spooler' -Force
$svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(60))
$svc.Refresh()
Write-Output "After:  $($svc.Status)"
