// Package service installs the agent as an OS service: a Windows service
// running as LocalSystem, or a macOS LaunchDaemon running as root.
package service

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Names used by both platforms.
const (
	WindowsServiceName = "CNAPPAgent"
	DisplayName        = "CNAPP Endpoint Agent"
	Description        = "Reports device inventory and security posture to the CNAPP server and runs allow-listed remote actions."
	LaunchdLabel       = "com.cloudsecurity.cnapp-agent"
)

// Options for Install.
type Options struct {
	Home string // optional --home passed to the service (non-default state/log location)
}

// copyFile copies src to dst (replacing it) with the given mode.
func copyFile(src, dst string, mode os.FileMode) error {
	if same(src, dst) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	_ = os.Remove(dst)
	if err := os.Rename(tmp, dst); err != nil {
		return fmt.Errorf("installing %s: %w", dst, err)
	}
	return os.Chmod(dst, mode)
}

// removeUpdateLeftovers deletes the self-update side files next to the binary
// (cnapp-agent.{new,old,failed,restore}[.exe]).
func removeUpdateLeftovers(bin string) {
	ext := filepath.Ext(bin)
	base := bin
	if ext != ".exe" {
		ext = ""
	} else {
		base = bin[:len(bin)-len(ext)]
	}
	for _, kind := range []string{"new", "old", "failed", "restore"} {
		_ = os.Remove(base + "." + kind + ext)
	}
}

func same(a, b string) bool {
	sa, err1 := os.Stat(a)
	sb, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(sa, sb)
}

func serviceArgs(o Options) []string {
	args := []string{"run"}
	if o.Home != "" {
		args = append(args, "--home", o.Home)
	}
	return args
}
