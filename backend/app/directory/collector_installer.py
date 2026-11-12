"""Pre-configured collector installers and setup scripts (Add directory >
Active Directory, and Connectors & scans > Collectors > Add collector).

What CI builds is bundled in the backend image next to the agent installers
(``AGENT_INSTALLERS_DIR``, listed with their SHA-256 in ``manifest.json``):
the generic collector MSI (``cnapp-collector-windows-x64.msi``, WiX, built
from endpoint-agent/packaging/windows/msi/cnapp-collector.wxs) and the
collector binaries (``cnapp-collector-windows-<arch>.exe``). A download is
built in memory:

* **MSI** (recommended, x64): a copy of the generic MSI whose ``CNAPP_PRESET``
  placeholder is overwritten in place with ``collector.json`` (below), exactly
  like the agent's pre-configured MSI (services/msipatch.py), plus a fresh
  package code and ProductCode, so a second download installs over the first
  as an upgrade. ``msiexec /i <file>.msi /qn [GMSA=..] [ALLOW_DOMAIN_CONTROLLER=1]``.
* **zip** (advanced / scripted, and Arm64; deprecated for x64):
  ``cnapp-collector.exe`` (byte for byte, SHA-256 checked against
  manifest.json), ``collector.json`` and ``Install-Collector.ps1`` /
  ``Uninstall-Collector.ps1`` wrappers around ``cnapp-collector install`` /
  ``uninstall --purge``.

``collector.json``: server URL, a fresh single-use collector enrollment token,
the private CA when the server certificate is not publicly trusted, the
service display name ("<BRAND_NAME> Collector") and the optional gMSA.

The plaintext token only exists inside the returned bytes.
"""
from __future__ import annotations

import io
import json
import re
import zipfile

from .. import config
from ..services import installers, msipatch

ARCHES = ("amd64", "arm64")
FORMATS = ("msi", "zip")
MSI_ARTIFACT = "cnapp-collector-windows-x64.msi"
TOKEN_RE = re.compile(r"^cnct_[A-Za-z0-9_\-]{8,124}$")
GMSA_RE = re.compile(r"^[A-Za-z0-9.-]{1,64}\\[A-Za-z0-9._-]{1,63}\$$")

InstallerUnavailable = installers.InstallerUnavailable
InstallerConfigError = installers.InstallerConfigError


def binary_name(arch: str) -> str:
    return f"cnapp-collector-windows-{arch}.exe"


def download_name(arch: str, fmt: str = "zip") -> str:
    if fmt == "msi":
        # e.g. Sentrigis-Collector.msi (what the console's install instructions show)
        brand = re.sub(r"[^A-Za-z0-9]+", "-", config.settings.brand_name).strip("-") or "CNAPP"
        return f"{brand}-Collector.msi"
    return f"collector-setup-windows-{arch}.zip"


def service_display_name() -> str:
    return f"{config.settings.brand_name} Collector"


def server_url() -> str | None:
    return installers.server_url_or_none()


def _binary(arch: str, *, verify: bool = True) -> tuple[bytes, str, str]:
    """(bytes, sha256, version) of the bundled collector binary."""
    if arch not in ARCHES:
        raise InstallerUnavailable(f"unsupported architecture {arch}")
    man = installers._manifest()
    name = binary_name(arch)
    expected = str((man.get("files") or {}).get(name, "")).lower()
    path = installers.installers_dir() / name
    if not path.is_file() or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise InstallerUnavailable(f"the collector binary {name} is not bundled with this server build (expected "
                                   f"{path} listed in manifest.json); use a CI-built backend image or set "
                                   "AGENT_INSTALLERS_DIR")
    data = path.read_bytes() if verify else b""
    if verify:
        import hashlib

        if hashlib.sha256(data).hexdigest() != expected:
            raise InstallerUnavailable(f"{name} does not match its SHA-256 in manifest.json; refusing to use it")
    return data, expected, str(man.get("version") or "unknown")


def _msi(*, verify: bool = True) -> tuple[bytes, str, str]:
    """(bytes, sha256, version) of the bundled generic collector MSI."""
    man = installers._manifest()
    expected = str((man.get("files") or {}).get(MSI_ARTIFACT, "")).lower()
    path = installers.installers_dir() / MSI_ARTIFACT
    if not path.is_file() or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise InstallerUnavailable(f"the collector MSI {MSI_ARTIFACT} is not bundled with this server build (expected "
                                   f"{path} listed in manifest.json); use a CI-built backend image, set "
                                   "AGENT_INSTALLERS_DIR, or download the zip (Advanced)")
    if path.stat().st_size > installers.MAX_ARTIFACT_BYTES:
        raise InstallerUnavailable(f"{path.name} is larger than {installers.MAX_ARTIFACT_BYTES} bytes")
    data = path.read_bytes() if verify else b""
    if verify:
        import hashlib

        if hashlib.sha256(data).hexdigest() != expected:
            raise InstallerUnavailable(f"{MSI_ARTIFACT} does not match its SHA-256 in manifest.json; refusing to use it")
    return data, expected, str(man.get("version") or "unknown")


def availability() -> dict:
    out = {"service_display_name": service_display_name(), "server_url": server_url(), "arches": {},
           "ca_configured": False}
    try:
        out["ca_configured"] = installers.server_ca_pem() is not None
    except InstallerConfigError:
        pass
    for arch in ARCHES:
        try:
            _, sha, version = _binary(arch, verify=False)
            out["arches"][arch] = {"available": True, "version": version, "filename": download_name(arch)}
        except InstallerUnavailable as e:
            out["arches"][arch] = {"available": False, "reason": str(e), "filename": download_name(arch)}
    try:
        _, _, version = _msi(verify=False)
        out["msi"] = {"available": True, "version": version, "filename": download_name("amd64", "msi"), "arch": "amd64"}
    except InstallerUnavailable as e:
        out["msi"] = {"available": False, "reason": str(e), "filename": download_name("amd64", "msi"), "arch": "amd64"}
    return out


def preset(server: str, token: str, ca_pem: str | None, gmsa: str, name: str) -> bytes:
    if not TOKEN_RE.fullmatch(token):
        raise ValueError("malformed collector enrollment token")
    if gmsa and not GMSA_RE.fullmatch(gmsa):
        raise ValueError("gMSA must look like DOMAIN\\name$")
    doc = {"version": 1, "kind": "collector", "server_url": server, "token": token, "name": name,
           "service_display_name": service_display_name()}
    if ca_pem:
        doc["ca_pem"] = ca_pem
    if gmsa:
        doc["run_as"] = gmsa
    return (json.dumps(doc, indent=2) + "\n").encode()


INSTALL_PS1 = r"""<#
.SYNOPSIS
  Installs the __DISPLAY__ (directory collector) from this folder.

.DESCRIPTION
  Run from an elevated PowerShell on a domain-joined Windows server (a member
  server is recommended, not a domain controller). The collector only makes
  outbound HTTPS connections to __SERVER__ and LDAP / Kerberos connections to
  your domain controllers; nothing listens.

  -Quiet         no prompts (for software deployment tools)
  -Gmsa          run the service as a group Managed Service Account (DOMAIN\name$)
                 instead of LocalSystem (the computer account); overrides collector.json
  -AllowDomainController   required with -Quiet when this host is a domain controller

.EXAMPLE
  .\Install-Collector.ps1
.EXAMPLE
  .\Install-Collector.ps1 -Quiet -Gmsa 'CORP\svc-collector$'
#>
[CmdletBinding()]
param([switch]$Quiet, [string]$Gmsa, [switch]$AllowDomainController)
$ErrorActionPreference = 'Stop'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run this script from an elevated PowerShell (Run as administrator).'
}
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe = Join-Path $here 'cnapp-collector.exe'
$preset = Join-Path $here 'collector.json'
$productType = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions').ProductType
if ($productType -eq 'LanmanNT') {
  $msg = 'WARNING: this host is a DOMAIN CONTROLLER. Domain controllers are your most sensitive servers; we ' +
         'recommend installing the collector on a member server. This collector cannot run commands, scripts ' +
         'or remote sessions (it only reads the directory), so installing it here is allowed.'
  Write-Warning $msg
  if ($Quiet -and -not $AllowDomainController) {
    throw 'Refusing a silent install on a domain controller without -AllowDomainController.'
  }
  if (-not $Quiet) {
    $answer = Read-Host 'Install on this domain controller anyway? (yes/no)'
    if ($answer -ne 'yes') { Write-Host 'Cancelled.'; exit 1 }
  }
}
$cliArgs = @('install', '--preset', $preset)
if ($Gmsa) { $cliArgs += @('--run-as', $Gmsa) }
& $exe @cliArgs
if ($LASTEXITCODE -ne 0) { throw "cnapp-collector install failed ($LASTEXITCODE)" }
Write-Host '__DISPLAY__ installed. It appears under Connectors & scans > Collectors within a minute.'
"""

UNINSTALL_PS1 = r"""<#
.SYNOPSIS
  Removes the __DISPLAY__: stops and deletes the service, its program files,
  credentials and logs. The collector's record stays in the console until you
  revoke and delete it there.
#>
$ErrorActionPreference = 'Stop'
$exe = Join-Path $env:ProgramFiles 'CNAPP Collector\cnapp-collector.exe'
if (-not (Test-Path $exe)) { $exe = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'cnapp-collector.exe' }
& $exe uninstall --purge
if ($LASTEXITCODE -ne 0) { throw "cnapp-collector uninstall failed ($LASTEXITCODE)" }
Write-Host '__DISPLAY__ removed.'
"""


def build_msi(token: str, *, include_ca: bool, gmsa: str, name: str) -> tuple[bytes, str, bool]:
    """The pre-configured collector MSI (x64), the collector version and whether the CA is in it."""
    server = installers.server_url()
    ca = installers.server_ca_pem() if include_ca else None
    base, _, version = _msi()
    doc = preset(server, token, ca, gmsa, name)
    if not installers._build_slots.acquire(timeout=60):
        raise InstallerUnavailable("too many installer builds in progress; try again shortly")
    try:
        data = msipatch.inject(base, doc, new_product_code=True)
    finally:
        installers._build_slots.release()
    return data, version, ca is not None


def build(arch: str, token: str, *, include_ca: bool, gmsa: str, name: str) -> tuple[bytes, str]:
    """The installer zip and the collector version."""
    server = installers.server_url()
    ca = installers.server_ca_pem() if include_ca else None
    data, _, version = _binary(arch)
    display = service_display_name()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("cnapp-collector.exe", data)
        z.writestr("collector.json", preset(server, token, ca, gmsa, name))
        z.writestr("Install-Collector.ps1", INSTALL_PS1.replace("__DISPLAY__", display).replace("__SERVER__", server))
        z.writestr("Uninstall-Collector.ps1", UNINSTALL_PS1.replace("__DISPLAY__", display))
        z.writestr("README.txt", (
            f"{display} {version}\r\n\r\n"
            "Advanced / scripted install. For x64 the MSI installer (Add directory > Active Directory, or\r\n"
            "Collectors > Add collector) is recommended: double-click, or msiexec /i <file>.msi /qn.\r\n"
            "Installing the MSI later takes this collector over and keeps its enrollment.\r\n\r\n"
            "Silent install (elevated):\r\n"
            "  powershell -ExecutionPolicy Bypass -File Install-Collector.ps1 -Quiet\r\n"
            "Run as a gMSA:\r\n  ... -File Install-Collector.ps1 -Quiet -Gmsa 'CORP\\svc-collector$'\r\n"
            "Uninstall:\r\n  powershell -ExecutionPolicy Bypass -File Uninstall-Collector.ps1\r\n\r\n"
            "collector.json holds a single-use enrollment token: delete this folder after installing.\r\n"))
    return buf.getvalue(), version


# ----------------------------------------------------------------------------- setup scripts
def _ps_quote(v: str) -> str:
    return "'" + v.replace("'", "''") + "'"


def setup_scripts(*, domain: str, gmsa: str, hosts: str) -> dict[str, str]:
    """PowerShell shown in the console for the gMSA setup and the optional manual
    pre-check. Values are placeholders the admin edits; nothing secret."""
    dom = domain.strip().lower() if re.fullmatch(r"[a-z0-9.-]{1,253}", domain.strip().lower()) else "corp.example.com"
    acct = gmsa.strip() if re.fullmatch(r"[A-Za-z0-9._-]{1,15}", gmsa.strip().rstrip("$")) else "svc-collector"
    acct = acct.rstrip("$")
    hlist = [h for h in re.split(r"[,\s]+", hosts) if re.fullmatch(r"[A-Za-z0-9-]{1,63}", h)] or ["COLLECTOR01"]
    principals = ", ".join(_ps_quote(h + "$") for h in hlist)
    netbios = dom.split(".")[0].upper()
    kds = """# 1. KDS root key (once per forest; needs Enterprise Admins / Domain Admins in the forest root).
#    In production the key is only usable after 10 hours (replication). Do NOT backdate it in production.
if (-not (Get-KdsRootKey)) {
    Add-KdsRootKey -EffectiveImmediately   # usable after ~10 hours
    # Lab only (single DC): Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))
}
Get-KdsRootKey | Format-List KeyId, EffectiveTime"""
    create = f"""# 2. The gMSA, allowed on the collector computer(s) only
#    (or a group: -PrincipalsAllowedToRetrieveManagedPassword 'Collector Hosts').
Import-Module ActiveDirectory
New-ADServiceAccount -Name {_ps_quote(acct)} -DNSHostName {_ps_quote(acct + '.' + dom)} `
    -PrincipalsAllowedToRetrieveManagedPassword {principals} `
    -KerberosEncryptionType AES128, AES256
# It needs no group membership: Domain Users read access is enough for every attribute collected."""
    grant = f"""# 3. Hardened OUs only (where Authenticated Users lost read access): grant the gMSA read on the synced OUs.
$ou = 'OU=Workstations,{','.join('DC=' + p for p in dom.split('.'))}'
dsacls $ou /I:T /G "{netbios}\\{acct}$:GR"   # generic read, inherited by child objects"""
    install = f"""# 4. On each collector host (elevated): install and test the gMSA (needs the RSAT AD PowerShell module).
#    A collector computer added to the principals must reboot (or run 'klist -li 0x3e7 purge') once.
Install-ADServiceAccount -Identity {_ps_quote(acct)}
Test-ADServiceAccount -Identity {_ps_quote(acct)}   # must print True"""
    switch = f"""# 5. Run the collector service as the gMSA. Easiest: install (or re-install) with
#      msiexec /i <Collector>.msi /qn GMSA={netbios}\\{acct}$
#    (zip: .\\Install-Collector.ps1 -Gmsa '{netbios}\\{acct}$'). Or switch an installed collector:
#    The gMSA needs "Log on as a service" (sc.exe grants it on member servers; check your GPO if it is managed).
sc.exe config CNAPPCollector obj= "{netbios}\\{acct}$" password= ""
Restart-Service CNAPPCollector
# Back to the computer account (LocalSystem):  sc.exe config CNAPPCollector obj= LocalSystem"""
    precheck = f"""# Optional manual pre-check (the console's Test runs the same checks ON the collector).
# Run on the collector host as the collector's identity (computer account: PsExec -s; gMSA: a scheduled task as the gMSA).
$domain = {_ps_quote(dom)}
$dcs = Resolve-DnsName -Type SRV "_ldap._tcp.dc._msdcs.$domain" | Where-Object Type -eq SRV
$dcs | Select-Object NameTarget, Port, Priority
foreach ($dc in $dcs.NameTarget) {{
    foreach ($port in 389, 636, 88) {{
        $ok = (Test-NetConnection $dc -Port $port -WarningAction SilentlyContinue).TcpTestSucceeded
        "{{0}}:{{1}} {{2}}" -f $dc, $port, $(if ($ok) {{ 'open' }} else {{ 'CLOSED / not responding (stale SRV record?)' }})
    }}
}}
# Kerberos bind with signing + sealing on 389 (no certificate needed), read 5 computers:
Add-Type -AssemblyName System.DirectoryServices.Protocols
$id = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($dcs[0].NameTarget, 389)
$c = New-Object System.DirectoryServices.Protocols.LdapConnection($id)
$c.AuthType = 'Negotiate'; $c.SessionOptions.Signing = $true; $c.SessionOptions.Sealing = $true
$c.Bind()
$base = 'DC=' + ($domain -replace '\\.', ',DC=')
$req = New-Object System.DirectoryServices.Protocols.SearchRequest($base, '(objectCategory=computer)', 'Subtree', 'cn')
$req.SizeLimit = 5
$c.SendRequest($req).Entries | ForEach-Object {{ $_.Attributes['cn'][0] }}"""
    return {"kds_root_key": kds, "create_gmsa": create, "grant_read": grant, "install_gmsa": install,
            "service_logon": switch, "precheck": precheck}
