//go:build windows

package update

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

const (
	createNoWindow         = 0x08000000
	detachedProcess        = 0x00000008
	createNewProcessGroup  = 0x00000200
	createBreakawayFromJob = 0x01000000
)

func hide(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
}

// startDetached starts the program outside the service process (and, if
// allowed, outside its job object) so it keeps running when the service exits.
func startDetached(name string, args []string) (*os.Process, error) {
	flags := []uint32{detachedProcess | createNewProcessGroup | createBreakawayFromJob, detachedProcess | createNewProcessGroup}
	var err error
	for _, f := range flags {
		cmd := exec.Command(name, args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: f}
		if err = cmd.Start(); err == nil {
			return cmd.Process, nil
		}
	}
	return nil, err
}

// verifyCodeSignature checks the Authenticode signature with the built-in
// PowerShell cmdlet (path passed via the environment, never interpolated).
func verifyCodeSignature(path, publisher string) error {
	script := `$s = Get-AuthenticodeSignature -LiteralPath $env:CNAPP_VERIFY_PATH; ` +
		`Write-Output ("{0}|{1}" -f $s.Status, $s.SignerCertificate.Subject)`
	cmd := exec.Command(powershell(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	cmd.Env = append(os.Environ(), "CNAPP_VERIFY_PATH="+path)
	hide(cmd)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("Get-AuthenticodeSignature: %w", err)
	}
	return checkAuthenticode(strings.TrimSpace(out.String()), publisher)
}

func powershell() string {
	if root := os.Getenv("SystemRoot"); root != "" {
		return root + `\System32\WindowsPowerShell\v1.0\powershell.exe`
	}
	return "powershell.exe"
}
