//go:build !windows

package collector

import (
	"os"
	"runtime"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/version"
)

// HostFacts: the collector is Windows-only; other platforms build for tests only.
func HostFacts() Facts {
	h, _ := os.Hostname()
	return Facts{Hostname: h, Architecture: runtime.GOARCH, Version: version.Version, RunAsKind: "unknown",
		Features: Features}
}
