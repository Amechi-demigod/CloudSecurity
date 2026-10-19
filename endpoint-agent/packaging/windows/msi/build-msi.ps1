<#
.SYNOPSIS
  Builds the generic (unconfigured) CNAPP agent MSI with the WiX Toolset v5.

.EXAMPLE
  .\build-msi.ps1 -AgentExe ..\..\..\dist\cnapp-agent-windows-amd64.exe -Version 0.1.42 -Output cnapp-agent-windows-x64.msi

.NOTES
  Signing: sign cnapp-agent.exe BEFORE building (it is embedded in the MSI), then
  sign the MSI itself, e.g. with signtool:
    signtool sign /fd sha256 /tr http://timestamp.digicert.com /td sha256 /f codesign.pfx /p <pw> cnapp-agent.exe
    signtool sign /fd sha256 /tr http://timestamp.digicert.com /td sha256 /f codesign.pfx /p <pw> cnapp-agent-windows-x64.msi
  A signed MSI must not be modified afterwards: the CNAPP console's pre-configured
  download edits the MSI, which invalidates a signature. Deploy a signed MSI with
  the CNAPP_SERVER / CNAPP_TOKEN properties instead (docs/DEVICE_MANAGEMENT.md).
#>
param(
  [Parameter(Mandatory = $true)][string]$AgentExe,
  [Parameter(Mandatory = $true)][string]$Version,
  [string]$Output = 'cnapp-agent-windows-x64.msi',
  [string]$WixVersion = '5.0.2'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# MSI ProductVersion is major.minor.build (each part numeric; build <= 65535).
if ($Version -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,5}$') { throw "Version must look like 0.1.42 (got '$Version')" }

if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
  dotnet tool install --global wix --version $WixVersion | Out-Host
  $env:PATH = "$env:PATH;$env:USERPROFILE\.dotnet\tools"
}
wix --version | Out-Host

$exe = (Resolve-Path -LiteralPath $AgentExe).Path
$wxs = Join-Path $PSScriptRoot 'cnapp-agent.wxs'
wix build $wxs -arch x64 -d "Version=$Version" -d "AgentExe=$exe" -o $Output
if ($LASTEXITCODE -ne 0) { throw "wix build failed ($LASTEXITCODE)" }
Get-Item $Output | Format-Table -AutoSize Name, Length
