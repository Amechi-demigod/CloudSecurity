// Package version holds the agent version, set at build time with
// -ldflags "-X github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/version.Version=1.2.3".
package version

import (
	"fmt"
	"runtime"
)

// Version of the agent binary.
var Version = "0.1.0-dev"

// Features lists optional capabilities of this agent build, sent to the server
// in the X-CNAPP-Agent-Features header so it only queues commands this agent
// understands (e.g. check_for_update; older agents get recheck_posture instead).
// host_isolation marks Suspend sign-in / Restore sign-in support (internal
// names kept for backend compatibility - see internal/signin); remote_session
// marks attended remote sessions (Windows only for now, internal/remote).
const Features = "check_for_update,host_isolation" + platformFeatures

// UserAgent is sent on every request to the server.
func UserAgent() string {
	return fmt.Sprintf("cnapp-agent/%s (%s; %s)", Version, runtime.GOOS, runtime.GOARCH)
}
