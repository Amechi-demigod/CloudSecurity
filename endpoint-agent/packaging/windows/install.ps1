<#
.SYNOPSIS
  Installs the CNAPP endpoint agent on Windows 10/11: enrolls it with your CNAPP
  server and registers the "CNAPP Endpoint Agent" service (LocalSystem).

.DESCRIPTION
  Run from an elevated PowerShell. Either point -BinaryPath at a downloaded
  cnapp-agent.exe, or give -DownloadUrl (and ideally -Sha256) to fetch it.
  With -RequireSignature the binary must carry a valid Authenticode signature
  (recommended once you sign releases; see docs/DEVICE_MANAGEMENT.md).

.EXAMPLE
  .\install.ps1 -Server https://cnapp.example.com -Token cne_xxx -BinaryPath .\cnapp-agent-windows-amd64.exe

.EXAMPLE
  # On-prem server with a certificate from an internal CA (cnapp-ctl tls export-ca, or your AD CS root):
  .\install.ps1 -Server https://cnapp.corp.local -Token cne_xxx -BinaryPath .\cnapp-agent-windows-amd64.exe -CaFile .\cnapp-root-ca.crt

.EXAMPLE
  .\install.ps1 -Server https://cnapp.example.com -Token cne_xxx `
     -DownloadUrl https://downloads.example.com/cnapp-agent-windows-amd64.exe -Sha256 <hex> -RequireSignature
#>
[CmdletBinding(DefaultParameterSetName = 'Local')]
param(
  [Parameter(Mandatory = $true)][string]$Server,
  [Parameter(Mandatory = $true)][string]$Token,
  [Parameter(ParameterSetName = 'Local')][string]$BinaryPath,
  [Parameter(ParameterSetName = 'Download', Mandatory = $true)][string]$DownloadUrl,
  [Parameter(ParameterSetName = 'Download')][string]$Sha256,
  [switch]$RequireSignature,
  # PEM file of a private/internal CA that issued the server certificate. The agent
  # keeps its own protected copy, so this file may be deleted afterwards. Not needed
  # when the CA is already trusted machine-wide (e.g. deployed by GPO).
  [string]$CaFile,
  [switch]$InsecureDev
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run this script from an elevated PowerShell (Run as administrator).'
}
if (-not $Server.StartsWith('https://') -and -not $InsecureDev) {
  throw 'The server URL must start with https:// (use -InsecureDev only for local testing).'
}

$tmp = $null
try {
  if ($PSCmdlet.ParameterSetName -eq 'Download') {
    if (-not $DownloadUrl.StartsWith('https://')) { throw 'DownloadUrl must be https://' }
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $tmp = Join-Path $env:TEMP ("cnapp-agent-" + [guid]::NewGuid().ToString('N') + '.exe')
    Write-Host "Downloading $DownloadUrl"
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $tmp -UseBasicParsing
    $BinaryPath = $tmp
    if ($Sha256) {
      $actual = (Get-FileHash -Algorithm SHA256 -Path $tmp).Hash
      if ($actual -ne $Sha256.ToUpperInvariant()) { throw "SHA-256 mismatch: expected $Sha256, got $actual" }
    } else {
      Write-Warning 'No -Sha256 given: the download is not integrity-checked.'
    }
  }
  if (-not $BinaryPath) {
    $BinaryPath = Join-Path $PSScriptRoot 'cnapp-agent.exe'
  }
  $BinaryPath = (Resolve-Path $BinaryPath).Path

  $sig = Get-AuthenticodeSignature -FilePath $BinaryPath
  if ($sig.Status -ne 'Valid') {
    if ($RequireSignature) { throw "Binary signature is not valid ($($sig.Status))." }
    Write-Warning "Binary is not Authenticode-signed ($($sig.Status)). Sign release builds before wide deployment."
  }

  $enrollArgs = @('enroll', '--server', $Server, '--token-stdin')
  if ($CaFile) {
    if (-not (Test-Path -LiteralPath $CaFile -PathType Leaf)) { throw "CA file not found: $CaFile" }
    $enrollArgs += @('--ca-file', (Resolve-Path -LiteralPath $CaFile).Path)
  }
  if ($InsecureDev) { $enrollArgs += '--insecure-dev' }
  # The token goes over stdin so it never appears in the process list.
  $Token | & $BinaryPath @enrollArgs
  if ($LASTEXITCODE -ne 0) { throw "Enrollment failed (exit code $LASTEXITCODE)." }

  & $BinaryPath install
  if ($LASTEXITCODE -ne 0) { throw "Service installation failed (exit code $LASTEXITCODE)." }

  Get-Service -Name CNAPPAgent | Format-Table -AutoSize Name, Status, StartType
  Write-Host 'CNAPP agent installed. The device appears in the console after its first check-in (within a minute).'
}
finally {
  if ($tmp -and (Test-Path $tmp)) { Remove-Item -Force $tmp }
}
