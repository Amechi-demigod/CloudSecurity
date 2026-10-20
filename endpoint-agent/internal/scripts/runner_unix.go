//go:build !windows

package scripts

import (
	"fmt"
	"os/exec"
	"syscall"
)

func interpreter(kind, script string) (string, []string, error) {
	switch kind {
	case "zsh":
		return "/bin/zsh", []string{"-f", script}, nil // -f: no startup files
	case "bash":
		return "/bin/bash", []string{"--noprofile", "--norc", script}, nil
	}
	return "", nil, fmt.Errorf("interpreter %q is not available on this OS", kind)
}

func prepare(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		// Kill the whole process group (children the script started).
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
