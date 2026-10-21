//go:build windows

package scripts

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
)

func interpreter(kind, script string) (string, []string, error) {
	if kind != "powershell" {
		return "", nil, fmt.Errorf("interpreter %q is not available on Windows", kind)
	}
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	ps := filepath.Join(root, `System32\WindowsPowerShell\v1.0\powershell.exe`)
	return ps, []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script}, nil
}

func prepare(cmd *exec.Cmd) {
	const createNoWindow = 0x08000000
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	cmd.Cancel = func() error {
		// Kill the whole tree (child processes the script started), then the process.
		root := os.Getenv("SystemRoot")
		if root == "" {
			root = `C:\Windows`
		}
		_ = exec.Command(filepath.Join(root, `System32\taskkill.exe`), "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid)).Run()
		return cmd.Process.Kill()
	}
}
