//go:build windows

package wipe

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
)

// probeScript only reads: the WMI class definition, `reagentc /info` and the edition.
const probeScript = `$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$r = [ordered]@{}
try {
  $c = Get-CimClass -Namespace 'root\cimv2\mdm\dmmap' -ClassName 'MDM_RemoteWipe'
  $r.mdm_bridge = $true
  $r.methods = @($c.CimClassMethods | ForEach-Object { $_.Name })
} catch { $r.mdm_bridge = $false; $r.mdm_error = $_.Exception.Message }
try { $r.reagentc = (& "$env:SystemRoot\System32\reagentc.exe" /info 2>&1 | Out-String) } catch { $r.reagentc_error = $_.Exception.Message }
try { $r.edition = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').EditionID } catch { }
$r | ConvertTo-Json -Compress`

// invokeScript calls one method; METHOD is replaced by a constant from Methods.
const invokeScript = `$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ns = 'root\cimv2\mdm\dmmap'
$session = New-CimSession
try {
  $inst = Get-CimInstance -Namespace $ns -ClassName 'MDM_RemoteWipe' -Filter "ParentID='./Vendor/MSFT' and InstanceID='RemoteWipe'"
  if (-not $inst) { throw 'MDM_RemoteWipe instance not found' }
  $params = New-Object Microsoft.Management.Infrastructure.CimMethodParametersCollection
  $params.Add([Microsoft.Management.Infrastructure.CimMethodParameter]::Create('param', '', 'String', 'In'))
  $res = $session.InvokeMethod($ns, $inst, 'METHOD', $params)
  'ReturnValue=' + $res.ReturnValue.Value
} finally { Remove-CimSession $session }`

func powershell(ctx context.Context, script string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	u := utf16.Encode([]rune(script))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		b[2*i], b[2*i+1] = byte(c), byte(c>>8)
	}
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	ps := filepath.Join(root, `System32\WindowsPowerShell\v1.0\powershell.exe`)
	cmd := exec.CommandContext(ctx, ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-EncodedCommand", base64.StdEncoding.EncodeToString(b))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	// stdout only: PowerShell writes progress records to stderr as CLIXML.
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil && stderr.Len() > 0 {
		err = fmt.Errorf("%w: %s", err, truncate(stripCLIXML(stderr.String()), 500))
	}
	return string(out), err
}

// Probe reports the wipe readiness of this Windows device (optIn from policy.json).
func Probe(ctx context.Context, optIn bool) Readiness {
	r := Readiness{OptIn: optIn, Supported: true}
	out, err := powershell(ctx, probeScript, 90*time.Second)
	var raw struct {
		MDMBridge     *bool    `json:"mdm_bridge"`
		Methods       []string `json:"methods"`
		MDMError      string   `json:"mdm_error"`
		Reagentc      string   `json:"reagentc"`
		ReagentcError string   `json:"reagentc_error"`
		Edition       string   `json:"edition"`
	}
	if err != nil || json.Unmarshal([]byte(jsonLine(out)), &raw) != nil {
		r.Error = fmt.Sprintf("probe failed: %v %s", err, truncate(out, 300))
		r.Finish()
		return r
	}
	r.MDMBridge, r.Methods, r.Edition = raw.MDMBridge, raw.Methods, raw.Edition
	r.WinREEnabled = ParseReagentc(raw.Reagentc)
	r.Error = strings.TrimSpace(raw.MDMError + " " + raw.ReagentcError)
	r.Finish()
	return r
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// WMIExecutor is the real executor (LocalSystem only).
type WMIExecutor struct{}

// Invoke calls MDM_RemoteWipe.<method>.
func (WMIExecutor) Invoke(ctx context.Context, method string) (string, error) {
	known := false
	for _, m := range Methods {
		known = known || m == method
	}
	if !known {
		return "", fmt.Errorf("unknown wipe method %q", method)
	}
	out, err := powershell(ctx, strings.Replace(invokeScript, "METHOD", method, 1), 5*time.Minute)
	if err != nil {
		return out, err
	}
	if v := strings.TrimSpace(lastLine(out)); strings.HasPrefix(v, "ReturnValue=") && v != "ReturnValue=" && v != "ReturnValue=0" {
		return out, fmt.Errorf("method returned %s", strings.TrimPrefix(v, "ReturnValue="))
	}
	return out, nil
}
