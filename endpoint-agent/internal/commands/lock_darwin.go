//go:build darwin

package commands

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const cgSession = "/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession"

// Lock locks the console session from the root LaunchDaemon.
//
// Supported mechanisms on current macOS, in order:
//  1. CGSession -suspend run in the console user's bootstrap context (switches
//     to the login window; the tool was removed in macOS 11+, so usually absent);
//  2. `pmset displaysleepnow`: puts the display to sleep. This locks the session
//     when "Require password after screen saver begins or display is turned off"
//     is "Immediately" (the macOS default); the result output reports the
//     user's actual setting so an admin can tell whether the screen is locked.
func Lock(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	uid, name := consoleUser()
	if uid == 0 {
		return "", fmt.Errorf("no user is logged in at the console; nothing to lock")
	}
	if _, err := os.Stat(cgSession); err == nil && os.Geteuid() == 0 {
		out, err := exec.CommandContext(ctx, "/bin/launchctl", "asuser", strconv.Itoa(uid), cgSession, "-suspend").CombinedOutput()
		if err == nil {
			return fmt.Sprintf("session of %s suspended to the login window (CGSession)", name), nil
		}
		_ = out
	}
	if out, err := exec.CommandContext(ctx, "/usr/bin/pmset", "displaysleepnow").CombinedOutput(); err != nil {
		return "", fmt.Errorf("pmset displaysleepnow: %v %s", err, strings.TrimSpace(string(out)))
	}
	setting := screenLockSetting(ctx, name)
	msg := fmt.Sprintf("display put to sleep for console user %s; screen lock setting: %s", name, setting)
	if strings.Contains(setting, "screenLock is off") {
		return msg, fmt.Errorf("the user does not require a password after sleep, so the screen is NOT locked")
	}
	return msg, nil
}

func consoleUser() (int, string) {
	st, err := os.Stat("/dev/console")
	if err != nil {
		return 0, ""
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, ""
	}
	name := strconv.Itoa(int(sys.Uid))
	if u, err := user.LookupId(name); err == nil {
		name = u.Username
	}
	return int(sys.Uid), name
}

func screenLockSetting(ctx context.Context, userName string) string {
	args := []string{"-screenLock", "status"}
	bin := "/usr/sbin/sysadminctl"
	if os.Geteuid() == 0 {
		bin, args = "/usr/bin/sudo", append([]string{"-n", "-u", userName, "/usr/sbin/sysadminctl"}, args...)
	}
	out, _ := exec.CommandContext(ctx, bin, args...).CombinedOutput()
	s := strings.TrimSpace(string(out))
	if i := strings.Index(s, "screenLock"); i >= 0 {
		return s[i:]
	}
	if s == "" {
		return "unknown"
	}
	return s
}
