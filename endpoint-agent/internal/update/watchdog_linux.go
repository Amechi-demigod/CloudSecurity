//go:build linux

package update

import (
	"fmt"
	"os"
	"os/exec"
	"time"
)

const systemdRun = "/usr/bin/systemd-run"

// startWatchdogUnit starts the rollback watchdog as a transient systemd
// service (it runs the PREVIOUS binary). used is false when systemd-run is not
// available or the agent is not running under systemd (containers, other init
// systems): the caller then starts it as a detached process.
//
// A transient unit lives outside the agent's own cgroup, so the service
// restart that follows the binary swap does not kill the watchdog.
func startWatchdogUnit(binary string, args []string) (used bool, err error) {
	if _, serr := os.Stat(systemdRun); serr != nil || os.Getenv("INVOCATION_ID") == "" {
		return false, nil
	}
	unit := fmt.Sprintf("cnapp-agent-update-watchdog-%d", time.Now().Unix())
	cmd := exec.Command(systemdRun, append([]string{"--quiet", "--collect", "--unit=" + unit, binary, "update-watchdog"}, args...)...)
	if _, rerr := cmd.CombinedOutput(); rerr != nil {
		return false, nil // fall back to a detached process
	}
	return true, nil
}
