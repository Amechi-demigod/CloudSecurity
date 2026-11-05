package directory

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Collector diagnostics (command collector_diagnostics, the console's "Test"):
// the checks an admin used to run by hand with PsExec, run ON the collector as
// its own identity, each reported pass / warn / fail / skip:
//
//  1. dc_locator: _ldap._tcp.dc._msdcs.<domain> (or the configured DCs);
//  2. port: TCP reachability of each DC (a located DC that refuses or times out
//     is flagged as a likely stale SRV record; the others are still tried);
//  3. certificate: TLS chain and host name (LDAPS / StartTLS; not needed sealed);
//  4. bind: Kerberos (computer account / gMSA) or the service account, and
//     whether the session is signed + sealed;
//  5. read: up to 5 computer objects.
//
// Read-only like directory_sync; the password (service account) never appears
// in the output.

// DiagParamKeys are the only parameters collector_diagnostics accepts.
var DiagParamKeys = []string{"source_id", "domain", "servers", "security", "port", "auth", "credential", "ca_pem",
	"base_dns"}

// ParseDiagParams validates collector_diagnostics parameters.
func ParseDiagParams(raw map[string]any) (*Params, error) {
	allowed := map[string]bool{}
	for _, k := range DiagParamKeys {
		allowed[k] = true
	}
	for k := range raw {
		if !allowed[k] {
			return nil, fmt.Errorf("unexpected parameter %q", k)
		}
	}
	p := &Params{Scopes: []string{ScopeComputers}, PageSize: MinPageSize}
	if err := parseConnection(raw, p); err != nil {
		return nil, err
	}
	return p, nil
}

// Step statuses.
const (
	StepPass = "pass"
	StepWarn = "warn"
	StepFail = "fail"
	StepSkip = "skip"
)

// Step is one diagnostic result.
type Step struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	Status     string `json:"status"`
	Detail     string `json:"detail"`
	DurationMS int    `json:"duration_ms"`
}

// DiagResult is reported as the command's result_data.
type DiagResult struct {
	Steps        []Step `json:"steps"`
	Transport    string `json:"transport"`
	SignedSealed bool   `json:"signed_sealed"`
	Server       string `json:"server"`
	Identity     string `json:"identity"`
}

// OK reports whether no step failed.
func (r DiagResult) OK() bool {
	for _, s := range r.Steps {
		if s.Status == StepFail {
			return false
		}
	}
	return true
}

// Diagnostics runs the checks; every dependency is replaceable in tests.
type Diagnostics struct {
	Locate   func(ctx context.Context, p *Params) ([]string, bool) // hosts, from DNS
	Dial     func(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error)
	TLSCheck func(ctx context.Context, p *Params, host string) error
	Connect  func(ctx context.Context, p *Params, host string) (Searcher, error)
	Identity string // the collector's service identity, e.g. CORP\HOST$
}

// DefaultDiagnostics uses DNS, TCP, TLS and the real LDAP backends.
func DefaultDiagnostics(identity string) *Diagnostics {
	return &Diagnostics{
		Locate: func(ctx context.Context, p *Params) ([]string, bool) {
			hosts := LocateDCs(ctx, p)
			fromDNS := len(p.Servers) == 0 && !(len(hosts) == 1 && hosts[0] == p.Domain)
			return hosts, fromDNS
		},
		Dial: func(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "tcp", addr)
		},
		TLSCheck: checkTLS,
		Connect:  connectOne,
		Identity: identity,
	}
}

func checkTLS(ctx context.Context, p *Params, host string) error {
	tc, err := TLSConfig(p, host)
	if err != nil {
		return err
	}
	addr := net.JoinHostPort(host, strconv.Itoa(p.Port))
	if p.Security == SecurityStartTLS {
		// Only the certificate is checked here; the bind step does the StartTLS exchange.
		return nil
	}
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: DialTimeout}, Config: tc}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return c.Close()
}

const diagReadLimit = 5

var errEnough = errors.New("enough objects read")

// Run executes the steps in order; later steps are skipped once one fails.
func (d *Diagnostics) Run(ctx context.Context, p *Params) DiagResult {
	res := DiagResult{Transport: p.Security, Identity: d.Identity}
	step := func(id, label string, fn func() (string, string)) bool {
		start := time.Now()
		status, detail := fn()
		res.Steps = append(res.Steps, Step{ID: id, Label: label, Status: status,
			Detail: Redact(detail, p.Secrets()...), DurationMS: int(time.Since(start) / time.Millisecond)})
		return status != StepFail
	}
	skipRest := func(ids ...[2]string) {
		for _, s := range ids {
			res.Steps = append(res.Steps, Step{ID: s[0], Label: s[1], Status: StepSkip, Detail: "skipped: an earlier check failed"})
		}
	}
	portLabel := fmt.Sprintf("Port %d reachable", p.Port)
	certLabel := "DC certificate (chain and host name)"
	bindLabel := "Bind as " + map[string]string{AuthKerberos: "the collector's identity", AuthSimple: "the service account"}[p.Auth]
	readLabel := "Read 5 objects"

	var hosts []string
	var fromDNS bool
	if !step("dc_locator", "Locate domain controllers", func() (string, string) {
		hosts, fromDNS = d.Locate(ctx, p)
		switch {
		case len(p.Servers) > 0:
			return StepPass, "configured: " + strings.Join(hosts, ", ")
		case !fromDNS:
			return StepWarn, "no _ldap._tcp.dc._msdcs." + p.Domain + " SRV records: trying the domain name itself"
		}
		return StepPass, fmt.Sprintf("%d from DNS: %s", len(hosts), strings.Join(hosts, ", "))
	}) {
		skipRest([2]string{"port", portLabel}, [2]string{"certificate", certLabel}, [2]string{"bind", bindLabel},
			[2]string{"read", readLabel})
		return res
	}
	var reachable []string
	if !step("port", portLabel, func() (string, string) {
		var notes []string
		for _, h := range hosts {
			c, err := d.Dial(ctx, net.JoinHostPort(h, strconv.Itoa(p.Port)), 5*time.Second)
			if err != nil {
				n := h + ": not reachable (" + err.Error() + ")"
				if fromDNS {
					n = h + ": " + StaleDCHint
				}
				notes = append(notes, n)
				continue
			}
			_ = c.Close()
			reachable = append(reachable, h)
		}
		if len(reachable) == 0 {
			return StepFail, strings.Join(notes, "; ")
		}
		detail := "reachable: " + strings.Join(reachable, ", ")
		if len(notes) > 0 {
			return StepWarn, detail + "; " + strings.Join(notes, "; ")
		}
		return StepPass, detail
	}) {
		skipRest([2]string{"certificate", certLabel}, [2]string{"bind", bindLabel}, [2]string{"read", readLabel})
		return res
	}
	if p.Security == SecuritySealed {
		step("certificate", certLabel, func() (string, string) {
			return StepSkip, "not needed: Kerberos signing and sealing on port " + strconv.Itoa(p.Port)
		})
	} else if !step("certificate", certLabel, func() (string, string) {
		if p.Security == SecurityStartTLS {
			return StepSkip, "checked during the StartTLS bind below"
		}
		if err := d.TLSCheck(ctx, p, reachable[0]); err != nil {
			return StepFail, reachable[0] + ": " + err.Error()
		}
		return StepPass, reachable[0] + ": certificate trusted, host name matches"
	}) {
		skipRest([2]string{"bind", bindLabel}, [2]string{"read", readLabel})
		return res
	}
	var s Searcher
	if !step("bind", bindLabel, func() (string, string) {
		var errs []string
		for _, h := range reachable {
			c, err := d.Connect(ctx, p, h)
			if err != nil {
				errs = append(errs, h+": "+err.Error())
				continue
			}
			s = c
			res.Server = h
			break
		}
		if s == nil {
			return StepFail, strings.Join(errs, "; ")
		}
		who := d.Identity
		if p.Auth == AuthSimple {
			who = "service account " + p.Username
		}
		detail := fmt.Sprintf("%s bound to %s as %s", transportLabel(p.Security), res.Server, who)
		if ss, ok := s.(interface{ Sealed() SealedState }); ok {
			st := ss.Sealed()
			res.SignedSealed = st.Signed && st.Sealed
			detail += fmt.Sprintf("; signed+sealed: %s", yesNo(res.SignedSealed))
		} else if p.Security != SecuritySealed {
			detail += "; protected by TLS"
		}
		return StepPass, detail
	}) {
		skipRest([2]string{"read", readLabel})
		return res
	}
	defer s.Close()
	step("read", readLabel, func() (string, string) {
		var names []string
		base := p.SearchBases()[0]
		err := s.Search(ctx, base, ComputerFilter, []string{"cn"}, MinPageSize, func(e Entry) error {
			names = append(names, e.str("cn", 64))
			if len(names) >= diagReadLimit {
				return errEnough
			}
			return nil
		})
		if err != nil && !errors.Is(err, errEnough) {
			return StepFail, base + ": " + err.Error()
		}
		if len(names) == 0 {
			return StepWarn, "no computer objects under " + base + " (empty, or no read access)"
		}
		return StepPass, fmt.Sprintf("%d object(s): %s", len(names), strings.Join(names, ", "))
	})
	return res
}

func transportLabel(sec string) string {
	switch sec {
	case SecuritySealed:
		return "Kerberos signing & sealing (LDAP 389)"
	case SecurityStartTLS:
		return "StartTLS"
	}
	return "LDAPS"
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
