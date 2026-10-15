//go:build !windows

package collect

import "os/exec"

func hideWindow(*exec.Cmd) {}
