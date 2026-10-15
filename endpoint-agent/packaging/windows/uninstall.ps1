<#
.SYNOPSIS
  Removes the CNAPP endpoint agent service. -Purge also deletes the device
  credential and logs under %ProgramData%\CNAPP Agent. Revoke or delete the
  device in the CNAPP console as well.
#>
param([switch]$Purge)
$ErrorActionPreference = 'Stop'
$exe = Join-Path $env:ProgramFiles 'CNAPP Agent\cnapp-agent.exe'
if (-not (Test-Path $exe)) { throw "Agent not found at $exe" }
# Run a copy: uninstall removes the installed binary.
$copy = Join-Path $env:TEMP ('cnapp-agent-uninstall-' + [guid]::NewGuid().ToString('N') + '.exe')
Copy-Item $exe $copy
try {
  $uninstallArgs = @('uninstall')
  if ($Purge) { $uninstallArgs += '--purge' }
  & $copy @uninstallArgs
  if ($LASTEXITCODE -ne 0) { throw "Uninstall failed (exit code $LASTEXITCODE)." }
} finally {
  Remove-Item -Force $copy -ErrorAction SilentlyContinue
}
