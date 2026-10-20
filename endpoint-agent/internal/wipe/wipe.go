// Package wipe implements the Windows-only remote wipe through the MDM Bridge
// WMI provider (namespace root\cimv2\mdm\dmmap, class MDM_RemoteWipe), which a
// LocalSystem service can call without the device being enrolled in an MDM.
//
// Methods (RemoteWipe CSP):
//   - doWipeProtectedMethod (default, mode "protected"): resets the PC and
//     cleans the drive; unlike doWipe it keeps retrying after a power cycle, so
//     a thief cannot stop it by switching the device off. Microsoft notes it may
//     leave some device configurations unable to boot.
//   - doWipeMethod (mode "standard"): the same reset ("remove everything"), but
//     it can be interrupted by power-cycling the device.
//   - doWipePersistUserDataMethod keeps user data: not offered (not a wipe).
//
// Both use the Windows Recovery Environment: if WinRE is disabled
// (`reagentc /info`), the reset fails. Readiness (WinRE, the WMI class and its
// methods, the local opt-in) is reported with every check-in.
//
// Safety: the device must have opted in at install time (policy.json, written
// only by the installer / a local administrator), the command must name this
// device's hostname, carry a short validity window, be executed at most once
// (the agent records the command id before running) and the agent sends a
// final acknowledgement to the server before it calls the method.
package wipe

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
)

// Modes and the WMI method each one calls (fixed; nothing from the server is
// ever interpolated into the PowerShell that invokes them).
var Methods = map[string]string{
	"protected": "doWipeProtectedMethod",
	"standard":  "doWipeMethod",
}

// MaxValidity is the longest validity window (issued_at -> expires_at) the
// agent accepts for a wipe command, whatever the server says.
const MaxValidity = 24*time.Hour + 5*time.Minute

// Readiness is what the agent reports about remote wipe (posture "remote_wipe").
type Readiness struct {
	OptIn        bool     `json:"opt_in"`
	Supported    bool     `json:"supported"`
	WinREEnabled *bool    `json:"winre_enabled"`
	MDMBridge    *bool    `json:"mdm_bridge"`
	Methods      []string `json:"methods,omitempty"`
	Method       string   `json:"method"`
	Edition      string   `json:"edition,omitempty"`
	Ready        bool     `json:"ready"`
	Detail       string   `json:"detail"`
	Error        string   `json:"error,omitempty"`
}

// Data converts r to a posture data map.
func (r Readiness) Data() map[string]any {
	m := map[string]any{"opt_in": r.OptIn, "supported": r.Supported, "winre_enabled": r.WinREEnabled,
		"mdm_bridge": r.MDMBridge, "method": r.Method, "ready": r.Ready}
	if len(r.Methods) > 0 {
		m["methods"] = r.Methods
	}
	if r.Edition != "" {
		m["edition"] = r.Edition
	}
	if r.Error != "" {
		m["error"] = r.Error
	}
	return m
}

// Finish fills Ready and Detail from the probed facts.
func (r *Readiness) Finish() {
	r.Method = Methods["protected"]
	var problems []string
	if !r.Supported {
		problems = append(problems, "remote wipe is only supported on Windows")
	}
	if !r.OptIn {
		problems = append(problems, "not opted in at install time (CNAPP_ALLOW_WIPE=1)")
	}
	if r.Supported && r.MDMBridge != nil && !*r.MDMBridge {
		problems = append(problems, "MDM_RemoteWipe WMI class not available")
	}
	if r.Supported && r.MDMBridge != nil && *r.MDMBridge && !contains(r.Methods, r.Method) {
		problems = append(problems, r.Method+" not available")
	}
	if r.Supported && r.WinREEnabled != nil && !*r.WinREEnabled {
		problems = append(problems, "Windows RE is disabled (reagentc /enable)")
	}
	unknown := r.Supported && (r.WinREEnabled == nil || r.MDMBridge == nil)
	r.Ready = len(problems) == 0 && !unknown
	switch {
	case len(problems) > 0:
		r.Detail = "remote wipe NOT ready: " + strings.Join(problems, "; ")
	case unknown:
		r.Detail = "remote wipe readiness partly unknown (could not query WinRE or WMI)"
	default:
		r.Detail = "remote wipe ready (" + r.Method + ", Windows RE enabled)"
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

var (
	guidRe     = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	statusLine = regexp.MustCompile(`(?i)Windows RE status:\s*(\S+)`)
)

// ParseReagentc decides from `reagentc /info` output whether WinRE is enabled.
// The English status line is used when present; otherwise (localized output)
// a non-zero BCD identifier means enabled and an all-zero one disabled.
func ParseReagentc(out string) *bool {
	t, f := true, false
	if m := statusLine.FindStringSubmatch(out); m != nil {
		switch strings.ToLower(m[1]) {
		case "enabled":
			return &t
		case "disabled":
			return &f
		}
	}
	for _, g := range guidRe.FindAllString(out, -1) {
		if strings.Trim(g, "0-") != "" {
			return &t
		}
		return &f
	}
	return nil
}

// Executor invokes the WMI method (replaced by a fake in tests).
type Executor interface {
	Invoke(ctx context.Context, method string) (string, error)
}

// Deps of Run.
type Deps struct {
	GOOS     string
	OptedIn  func() (bool, error)
	Hostname func() string
	Probe    func(ctx context.Context) Readiness
	// Ack sends the final acknowledgement; the wipe only starts when it succeeds.
	Ack  func(ctx context.Context) error
	Exec Executor
}

// Outcome of a wipe command.
type Outcome struct {
	Status string // succeeded | failed | rejected
	Output string
}

// ErrRejected marks refused commands.
var ErrRejected = errors.New("rejected")

// ValidateParams checks the wipe parameters and validity window.
func ValidateParams(c model.Command) error {
	mode, ok := c.Params["mode"].(string)
	if _, known := Methods[mode]; !ok || !known {
		return fmt.Errorf("mode must be one of protected, standard")
	}
	if h, ok := c.Params["hostname"].(string); !ok || strings.TrimSpace(h) == "" {
		return errors.New("hostname is required")
	}
	if c.IssuedAt.IsZero() || c.ExpiresAt.IsZero() {
		return errors.New("wipe commands need issued_at and expires_at")
	}
	if c.ExpiresAt.Sub(c.IssuedAt) > MaxValidity {
		return fmt.Errorf("validity window %s is longer than the %s the agent accepts", c.ExpiresAt.Sub(c.IssuedAt), MaxValidity)
	}
	return nil
}

// Run executes a validated wipe_device command.
func Run(ctx context.Context, c model.Command, d Deps) Outcome {
	if d.GOOS != "windows" {
		return Outcome{"rejected", "remote wipe is only supported on Windows (a Mac needs an Apple MDM to erase)"}
	}
	if err := ValidateParams(c); err != nil {
		return Outcome{"rejected", err.Error()}
	}
	opted, err := d.OptedIn()
	if err != nil {
		return Outcome{"rejected", "cannot read the local wipe opt-in: " + err.Error()}
	}
	if !opted {
		return Outcome{"rejected", "remote wipe is not enabled on this device: it must opt in at install time " +
			"(MSI property CNAPP_ALLOW_WIPE=1 or the console's 'Allow remote wipe' installer option)"}
	}
	want := strings.TrimSpace(c.Params["hostname"].(string))
	if have := d.Hostname(); !strings.EqualFold(want, have) {
		return Outcome{"rejected", fmt.Sprintf("command is for device %q but this device is %q", want, have)}
	}
	r := d.Probe(ctx)
	if r.WinREEnabled != nil && !*r.WinREEnabled {
		return Outcome{"failed", "Windows RE is disabled, the reset would fail: run `reagentc /enable` first. " + r.Detail}
	}
	if r.MDMBridge != nil && !*r.MDMBridge {
		return Outcome{"failed", "the MDM_RemoteWipe WMI class is not available on this Windows: " + r.Error}
	}
	method := Methods[c.Params["mode"].(string)]
	if err := d.Ack(ctx); err != nil {
		return Outcome{"failed", "the server did not confirm the final acknowledgement; not wiping: " + err.Error()}
	}
	out, err := d.Exec.Invoke(ctx, method)
	if err != nil {
		return Outcome{"failed", fmt.Sprintf("%s failed: %v %s", method, err, strings.TrimSpace(out))}
	}
	return Outcome{"succeeded", fmt.Sprintf("%s accepted (%s); Windows restarts into the recovery environment and "+
		"resets the device. The agent and its credential are removed by the reset.", method, strings.TrimSpace(out))}
}
