//go:build darwin

package service

import (
	"context"
	"errors"
	"fmt"
	"html"
	"os"
	"os/exec"
	"strings"
)

// Install locations on macOS.
const (
	BinaryPath = "/usr/local/cnapp-agent/bin/cnapp-agent"
	PlistPath  = "/Library/LaunchDaemons/" + LaunchdLabel + ".plist"
	launchctl  = "/bin/launchctl"
)

// IsService reports whether the process was started by the OS service manager
// (always false here: launchd runs `cnapp-agent run` like a normal process).
func IsService() bool { return false }

// RunService is unused on macOS.
func RunService(func(ctx context.Context) error) error { return errors.New("not a Windows service") }

func plist(args []string) string {
	var b strings.Builder
	for _, a := range append([]string{BinaryPath}, args...) {
		b.WriteString("\t\t<string>" + html.EscapeString(a) + "</string>\n")
	}
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + LaunchdLabel + `</string>
	<key>ProgramArguments</key>
	<array>
` + b.String() + `	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>30</integer>
	<key>ProcessType</key>
	<string>Background</string>
	<key>StandardOutPath</key>
	<string>/Library/Logs/CNAPP Agent/launchd.log</string>
	<key>StandardErrorPath</key>
	<string>/Library/Logs/CNAPP Agent/launchd.log</string>
</dict>
</plist>
`
}

func lc(args ...string) error {
	out, err := exec.Command(launchctl, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl %s: %v %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Install copies the running binary to BinaryPath, writes the LaunchDaemon and starts it.
func Install(o Options) error {
	if os.Geteuid() != 0 {
		return errors.New("install must run as root (sudo)")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	_ = lc("bootout", "system/"+LaunchdLabel) // upgrade: stop the old instance first
	if err := copyFile(exe, BinaryPath, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll("/Library/Logs/CNAPP Agent", 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(PlistPath, []byte(plist(serviceArgs(o))), 0o644); err != nil {
		return err
	}
	if err := os.Chown(PlistPath, 0, 0); err != nil {
		return err
	}
	if err := lc("bootstrap", "system", PlistPath); err != nil {
		return err
	}
	_ = lc("enable", "system/"+LaunchdLabel)
	return lc("kickstart", "-k", "system/"+LaunchdLabel)
}

// Uninstall stops and removes the LaunchDaemon and the installed binary.
func Uninstall() error {
	if os.Geteuid() != 0 {
		return errors.New("uninstall must run as root (sudo)")
	}
	_ = lc("bootout", "system/"+LaunchdLabel)
	for _, p := range []string{PlistPath, BinaryPath} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	_ = os.Remove("/usr/local/cnapp-agent/bin")
	_ = os.Remove("/usr/local/cnapp-agent")
	return nil
}

// ConfigureRecovery is a no-op outside Windows (launchd KeepAlive restarts the agent).
func ConfigureRecovery() error { return nil }
