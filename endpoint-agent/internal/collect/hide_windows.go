//go:build windows

package collect

import (
	"os/exec"
	"syscall"
)

// hideWindow prevents a console window from flashing when a command runs in a user session.
func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
}
