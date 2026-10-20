//go:build !windows

package update

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
)

func hide(*exec.Cmd) {}

// startDetached starts cmd in its own session so launchd does not kill it
// together with the agent's process group when the agent exits.
func startDetached(name string, args []string) (*os.Process, error) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd.Process, nil
}

func verifyCodeSignature(path, team string) error {
	if runtime.GOOS != "darwin" {
		return errors.New("platform code signing verification is only implemented for Windows and macOS")
	}
	if out, err := exec.Command("/usr/bin/codesign", "--verify", "--strict", path).CombinedOutput(); err != nil {
		return fmt.Errorf("codesign --verify: %v %s", err, bytes.TrimSpace(out))
	}
	out, err := exec.Command("/usr/bin/codesign", "-dv", "--verbose=2", path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("codesign -dv: %v", err)
	}
	return checkCodesign(string(out), team)
}
