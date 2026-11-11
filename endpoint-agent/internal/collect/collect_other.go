//go:build !windows && !darwin && !linux

package collect

import (
	"context"
	"os"
	"strings"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
)

// This operating system is not supported: only the common inventory is
// collected and the posture checks are reported as unknown.
func platformCollect(_ context.Context, c collector, _ Options) {
	c.r.Device.OSName = "Unsupported OS"
	for _, name := range []string{"disk_encryption", "firewall", "antivirus"} {
		c.r.Posture[name] = model.Unknown("not supported on this platform", nil)
	}
}

func rawMachineID(context.Context) (string, error) {
	b, err := os.ReadFile("/etc/machine-id")
	return strings.TrimSpace(string(b)), err
}
