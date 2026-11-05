//go:build !windows && !darwin

package collect

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
)

// Linux is not supported yet: only the common inventory is collected and all
// posture checks are reported as unknown. Add collect_linux.go to extend.
func platformCollect(ctx context.Context, c collector, _ Options) {
	c.r.Device.OSName = "Linux"
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(l, "PRETTY_NAME="); ok {
				c.r.Device.OSName = strings.Trim(v, `"`)
			}
		}
	}
	c.r.Device.DirectoryJoin = linuxJoin(ctx, c.r.Device.Hostname)
	c.guard("classification", func() error {
		c.r.Device.Classification = linuxClassification()
		return nil
	})
	for _, name := range []string{"disk_encryption", "firewall", "antivirus"} {
		c.r.Posture[name] = model.Unknown("not supported on this platform yet", nil)
	}
}

func rawMachineID(context.Context) (string, error) {
	b, err := os.ReadFile("/etc/machine-id")
	return strings.TrimSpace(string(b)), err
}

// linuxJoin reports the realmd (AD / Kerberos) membership, if any. Missing
// realmd or a failure is not an error: most Linux hosts are not joined.
func linuxJoin(ctx context.Context, hostname string) *model.DirectoryJoin {
	for _, bin := range []string{"/usr/sbin/realm", "/usr/bin/realm"} {
		if _, err := os.Stat(bin); err != nil {
			continue
		}
		out, err := Run(ctx, 20*time.Second, bin, "list")
		if err != nil {
			return nil
		}
		return ParseRealmList(string(out), hostname)
	}
	return nil
}

// linuxClassification: DMI facts, CPUID and the role heuristic (LinuxRole).
func linuxClassification() *model.Classification {
	f := ReadDMIDir("/sys/class/dmi/id")
	f.CPUIDVendor = cpuidHypervisor()
	c := &model.Classification{}
	classifyFirmware(f, c)
	c.Role, c.RoleSource = LinuxRole(c, GraphicalDefaultTarget("/"))
	return c
}
