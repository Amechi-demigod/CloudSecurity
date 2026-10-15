//go:build !windows && !darwin

package collect

import (
	"context"
	"os"
	"strings"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
)

// Linux is not supported yet: only the common inventory is collected and all
// posture checks are reported as unknown. Add collect_linux.go to extend.
func platformCollect(_ context.Context, c collector, _ Options) {
	c.r.Device.OSName = "Linux"
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(l, "PRETTY_NAME="); ok {
				c.r.Device.OSName = strings.Trim(v, `"`)
			}
		}
	}
	for _, name := range []string{"disk_encryption", "firewall", "antivirus"} {
		c.r.Posture[name] = model.Unknown("not supported on this platform yet", nil)
	}
}

func rawMachineID(context.Context) (string, error) {
	b, err := os.ReadFile("/etc/machine-id")
	return strings.TrimSpace(string(b)), err
}
