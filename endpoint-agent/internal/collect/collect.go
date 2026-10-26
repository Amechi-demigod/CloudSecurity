// Package collect gathers read-only device inventory, security posture and
// installed software using OS-native commands and APIs.
//
// Every collector runs with a timeout and inside a panic guard: a failing
// collector yields an "unknown" posture check and an entry in Report.Errors,
// never a crash. Parsers live in OS-independent files (windows.go, macos.go)
// so their tests run on any platform against fixture outputs in testdata/.
package collect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/commands"
)

// Options select what to collect.
type Options struct {
	Software bool // installed software (slower; sent on every full check-in)
}

// DefaultTimeout bounds each external command.
const DefaultTimeout = 60 * time.Second

// maxOutput caps captured command output.
const maxOutput = 8 << 20

// Run executes an OS command with a timeout and returns its stdout (stderr is
// appended when stdout is empty, since some macOS tools print results there).
// Commands are always invoked by absolute path with fixed arguments; no shell.
var Run = func(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr limitedBuffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	hideWindow(cmd)
	err := cmd.Run()
	out := stdout.b
	if len(strings.TrimSpace(string(out))) == 0 {
		out = stderr.b
	}
	if ctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("%s timed out after %s", name, timeout)
	}
	if err != nil {
		msg := strings.TrimSpace(string(stderr.b))
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return out, fmt.Errorf("%s: %w %s", name, err, msg)
	}
	return out, nil
}

type limitedBuffer struct{ b []byte }

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := maxOutput - len(l.b); room > 0 {
		if len(p) > room {
			l.b = append(l.b, p[:room]...)
		} else {
			l.b = append(l.b, p...)
		}
	}
	return len(p), nil
}

// collector records results into the report under a name.
type collector struct {
	r *model.Report
}

// guard runs fn, converting panics and errors into Report.Errors[name].
func (c collector) guard(name string, fn func() error) {
	defer func() {
		if p := recover(); p != nil {
			slog.Error("collector panicked", "collector", name, "panic", p, "stack", string(debug.Stack()))
			c.r.Errors[name] = fmt.Sprintf("collector panicked: %v", p)
		}
	}()
	if err := fn(); err != nil {
		slog.Warn("collector failed", "collector", name, "err", err)
		c.r.Errors[name] = err.Error()
	}
}

// posture runs a posture check; on error or panic the check becomes "unknown".
func (c collector) posture(name string, fn func() (model.PostureCheck, error)) {
	var res model.PostureCheck
	var ferr error
	func() {
		defer func() {
			if p := recover(); p != nil {
				slog.Error("posture check panicked", "check", name, "panic", p)
				ferr = fmt.Errorf("check panicked: %v", p)
			}
		}()
		res, ferr = fn()
	}()
	if ferr != nil {
		if res.Status == "" {
			res = model.Unknown("could not determine", ferr)
		} else if res.Error == nil {
			msg := ferr.Error()
			res.Error = &msg
		}
		c.r.Errors[name] = ferr.Error()
	}
	if res.Data == nil {
		res.Data = map[string]any{}
	}
	c.r.Posture[name] = res
}

// Collect gathers a full report. It never returns an error: failures are recorded in the report.
func Collect(ctx context.Context, o Options) *model.Report {
	r := &model.Report{
		SchemaVersion: 1,
		CollectedAt:   time.Now().UTC().Truncate(time.Second),
		Posture:       map[string]model.PostureCheck{},
		Errors:        map[string]string{},
	}
	c := collector{r: r}
	c.guard("common", func() error { return collectCommon(r) })
	platformCollect(ctx, c, o)
	r.Normalize()
	c.r.Posture["host_isolation"] = model.PostureCheck{Status: "succeeded", Data: map[string]any{"isolated": commands.Isolated()}}
	return r
}

func collectCommon(r *model.Report) error {
	d := &r.Device
	d.OSFamily = osFamily()
	d.Architecture = runtime.GOARCH
	d.AgentVersion = version.Version
	if h, err := os.Hostname(); err == nil {
		d.Hostname = h
	}
	d.Timezone = time.Now().Location().String()
	if d.Timezone == "Local" {
		d.Timezone, _ = time.Now().Zone()
	}
	ifs, err := interfaces()
	d.Network = ifs
	return err
}

func osFamily() string {
	switch runtime.GOOS {
	case "darwin":
		return "macos"
	default:
		c.r.Posture["host_isolation"] = model.PostureCheck{Status: "succeeded", Data: map[string]any{"isolated": commands.Isolated()}}
	return runtime.GOOS
	}
}

// interfaces lists up, non-loopback adapters that have a MAC address.
func interfaces() ([]model.NetInterface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := []model.NetInterface{}
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 || i.Flags&net.FlagUp == 0 || len(i.HardwareAddr) == 0 {
			continue
		}
		ni := model.NetInterface{Name: i.Name, MAC: i.HardwareAddr.String(), IPs: []string{}}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLinkLocalUnicast() {
				ni.IPs = append(ni.IPs, ipn.IP.String())
			}
		}
		if len(ni.IPs) == 0 {
			continue // skip idle virtual adapters
		}
		out = append(out, ni)
	}
	slices.SortFunc(out, func(a, b model.NetInterface) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// HashMachineID returns the hex SHA-256 of a raw machine identifier ("" stays "").
func HashMachineID(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("cnapp-agent:" + raw))
	return hex.EncodeToString(sum[:])
}

// MachineID returns the hashed OS machine identifier used to recognise re-enrollment.
func MachineID(ctx context.Context) string {
	id, err := rawMachineID(ctx)
	if err != nil {
		slog.Warn("machine id unavailable", "err", err)
	}
	return HashMachineID(id)
}

var errUnsupported = errors.New("not supported on this platform")

func i64(v int64) *int64 { return &v }
func iptr(v int) *int    { return &v }
