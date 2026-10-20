//go:build darwin

package lostmode

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const loginwindowPlist = "/Library/Preferences/com.apple.loginwindow"

type macBackend struct{}

func platformBackend() Backend { return macBackend{} }

func (macBackend) Name() string { return "lock screen / login window message (LoginwindowText)" }

func defaults(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/bin/defaults", args...).CombinedOutput()
	return strings.TrimRight(string(out), "\n"), err
}

func (macBackend) Get(ctx context.Context) (Notice, error) {
	out, err := defaults(ctx, "read", loginwindowPlist, "LoginwindowText")
	if err != nil {
		// `defaults read` exits 1 when the key does not exist.
		if strings.Contains(out, "does not exist") {
			return Notice{}, nil
		}
		return Notice{}, fmt.Errorf("defaults read: %v %s", err, out)
	}
	return Notice{Text: out, TextSet: true}, nil
}

func (b macBackend) Set(ctx context.Context, n Notice) error {
	text := strings.ReplaceAll(n.Caption+"\n"+n.Text, "\r\n", "\n")
	if out, err := defaults(ctx, "write", loginwindowPlist, "LoginwindowText", "-string", text); err != nil {
		return fmt.Errorf("defaults write: %v %s", err, out)
	}
	updatePreboot(ctx)
	return nil
}

func (macBackend) Restore(ctx context.Context, n Notice) error {
	var out string
	var err error
	if n.TextSet {
		out, err = defaults(ctx, "write", loginwindowPlist, "LoginwindowText", "-string", n.Text)
	} else {
		out, err = defaults(ctx, "delete", loginwindowPlist, "LoginwindowText")
		if err != nil && strings.Contains(out, "does not exist") {
			err = nil
		}
	}
	if err != nil {
		return fmt.Errorf("defaults: %v %s", err, out)
	}
	updatePreboot(ctx)
	return nil
}

// updatePreboot copies the login window settings to the Preboot volume so the
// FileVault unlock screen shows the current message (best effort).
func updatePreboot(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	_ = exec.CommandContext(ctx, "/usr/sbin/diskutil", "apfs", "updatePreboot", "/").Run()
}
