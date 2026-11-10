package netscan

import (
	"fmt"
	"log/slog"
	"math"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Command types.
const (
	CmdScan    = "network_scan"
	CmdSubnets = "network_subnets"
)

// AllowedParams are the only parameters network_scan accepts.
var AllowedParams = []string{"scan_id", "targets", "exclude", "port_check", "ports", "concurrency", "timeout_ms", "snmp",
	"upload_url"}

// Port is one port of the light port check.
type Port struct {
	Port  int
	Proto string // tcp | udp
}

// Credential is one SNMP credential. It holds secrets: it never formats,
// marshals or logs them (every printing path below is redacted).
type Credential struct {
	ID           any // as delivered (string or number); echoed back as credential_id
	Version      string
	Username     string
	AuthProto    string
	PrivProto    string
	Level        string
	AuthPassword string
	PrivPassword string
	Community    string
}

func (c Credential) redacted() string {
	return fmt.Sprintf("snmp credential id=%v version=%s [secrets redacted]", c.ID, c.Version)
}

// String, GoString, MarshalJSON, MarshalText and LogValue keep secrets out of
// every formatting path.
func (c Credential) String() string               { return c.redacted() }
func (c Credential) GoString() string             { return c.redacted() }
func (c Credential) MarshalText() ([]byte, error) { return []byte(c.redacted()), nil }
func (c Credential) MarshalJSON() ([]byte, error) { return []byte(`"` + c.redacted() + `"`), nil }
func (c Credential) LogValue() slog.Value         { return slog.StringValue(c.redacted()) }

// Params is a validated network_scan command.
type Params struct {
	ScanID      string
	Targets     []string
	Exclude     []string
	Set         *AddrSet
	PortCheck   bool
	Ports       []Port
	Concurrency int
	Timeout     time.Duration
	SNMP        []Credential
	UploadURL   string
}

// Secrets lists every secret value of the command (for output redaction).
func (p *Params) Secrets() []string {
	var out []string
	for _, c := range p.SNMP {
		for _, s := range []string{c.Community, c.AuthPassword, c.PrivPassword} {
			if s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

func (p *Params) String() string {
	return fmt.Sprintf("network_scan %s (%d addresses, %d snmp credentials)", p.ScanID, p.Set.Count(), len(p.SNMP))
}

func (p *Params) LogValue() slog.Value {
	return slog.GroupValue(slog.String("scan_id", p.ScanID), slog.Int("addresses", p.Set.Count()),
		slog.Int("snmp_credentials", len(p.SNMP)), slog.Int("concurrency", p.Concurrency),
		slog.Bool("port_check", p.PortCheck))
}

// DefaultPorts is the light port check when the server sends none.
var DefaultPorts = []Port{{21, "tcp"}, {22, "tcp"}, {23, "tcp"}, {80, "tcp"}, {443, "tcp"}, {445, "tcp"},
	{3389, "tcp"}, {8080, "tcp"}, {8443, "tcp"}, {161, "udp"}}

var scanIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

const (
	maxPorts       = 100
	maxCredentials = 16
	maxSecretLen   = 256
)

// ParseParams validates a delivered network_scan command (nothing is
// trusted: IPv4 only, limits and forbidden blocks enforced here).
func ParseParams(raw map[string]any) (*Params, error) {
	return parseParams(raw, false)
}

func parseParams(raw map[string]any, allowReserved bool) (*Params, error) {
	allowed := map[string]bool{}
	for _, k := range AllowedParams {
		allowed[k] = true
	}
	for k := range raw {
		if !allowed[k] {
			return nil, fmt.Errorf("unexpected parameter %q", k)
		}
	}
	p := &Params{Concurrency: 20, Timeout: time.Second}
	var err error
	if p.ScanID, err = strParam(raw, "scan_id", true); err != nil {
		return nil, err
	}
	if !scanIDRe.MatchString(p.ScanID) {
		return nil, fmt.Errorf("scan_id must be 1-64 characters: letters, digits, '-' and '_'")
	}
	if p.Targets, err = strList(raw, "targets"); err != nil {
		return nil, err
	}
	if p.Exclude, err = strList(raw, "exclude"); err != nil {
		return nil, err
	}
	if p.Set, err = parseTargets(p.Targets, p.Exclude, allowReserved); err != nil {
		return nil, err
	}
	if v, ok := raw["port_check"]; ok && v != nil {
		if p.PortCheck, ok = v.(bool); !ok {
			return nil, fmt.Errorf("port_check must be true or false")
		}
	}
	if p.PortCheck {
		if p.Ports, err = parsePorts(raw["ports"]); err != nil {
			return nil, err
		}
		if len(p.Ports) == 0 {
			p.Ports = append([]Port(nil), DefaultPorts...)
		}
	}
	if v, ok := raw["concurrency"]; ok && v != nil {
		n, err := intParam(v, "concurrency", 1, 64)
		if err != nil {
			return nil, err
		}
		p.Concurrency = n
	}
	if v, ok := raw["timeout_ms"]; ok && v != nil {
		n, err := intParam(v, "timeout_ms", 100, 30000)
		if err != nil {
			return nil, err
		}
		p.Timeout = time.Duration(n) * time.Millisecond
	}
	if p.SNMP, err = parseCreds(raw["snmp"]); err != nil {
		return nil, err
	}
	if p.UploadURL, err = strParam(raw, "upload_url", true); err != nil {
		return nil, err
	}
	if _, err := UploadPath(p.UploadURL, ""); err != nil {
		return nil, err
	}
	return p, nil
}

// UploadPath reduces upload_url to a server-relative path under
// /api/collector/. An absolute URL is accepted only when its host equals
// serverHost (when serverHost is empty, only paths are accepted at parse
// time); credentials, queries and fragments are refused.
func UploadPath(raw, serverHost string) (string, error) {
	bad := fmt.Errorf("upload_url must be a path under /api/collector/ on the enrolled server")
	s := raw
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return "", bad
		}
		if serverHost != "" && !strings.EqualFold(u.Host, serverHost) {
			return "", bad
		}
		s = u.Path
	}
	if !strings.HasPrefix(s, "/api/collector/") || len(s) > 300 || strings.Contains(s, "..") ||
		strings.ContainsAny(s, "?# \\\r\n\t") {
		return "", bad
	}
	return s, nil
}

func strParam(raw map[string]any, key string, required bool) (string, error) {
	v, ok := raw[key]
	if !ok || v == nil {
		if required {
			return "", fmt.Errorf("%s is required", key)
		}
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", key)
	}
	return strings.TrimSpace(s), nil
}

func strList(raw map[string]any, key string) ([]string, error) {
	v, ok := raw[key]
	if !ok || v == nil {
		return nil, nil
	}
	l, ok := v.([]any)
	if !ok {
		if ss, ok2 := v.([]string); ok2 {
			return ss, nil
		}
		return nil, fmt.Errorf("%s must be a list of strings", key)
	}
	out := make([]string, 0, len(l))
	for _, e := range l {
		s, ok := e.(string)
		if !ok {
			return nil, fmt.Errorf("%s must be a list of strings", key)
		}
		out = append(out, s)
	}
	return out, nil
}

func intParam(v any, name string, lo, hi int) (int, error) {
	var f float64
	switch x := v.(type) {
	case float64:
		f = x
	case int:
		f = float64(x)
	default:
		return 0, fmt.Errorf("%s must be a number", name)
	}
	if f != math.Trunc(f) || f < float64(lo) || f > float64(hi) {
		return 0, fmt.Errorf("%s must be an integer between %d and %d", name, lo, hi)
	}
	return int(f), nil
}

func parsePorts(v any) ([]Port, error) {
	if v == nil {
		return nil, nil
	}
	l, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("ports must be a list")
	}
	if len(l) > maxPorts {
		return nil, fmt.Errorf("at most %d ports", maxPorts)
	}
	var out []Port
	seen := map[Port]bool{}
	for _, e := range l {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("each port must be an object {port, proto}")
		}
		n, err := intParam(m["port"], "port", 1, 65535)
		if err != nil {
			return nil, err
		}
		proto, _ := m["proto"].(string)
		proto = strings.ToLower(proto)
		if proto == "" {
			proto = "tcp"
		}
		if proto != "tcp" && proto != "udp" {
			return nil, fmt.Errorf("port proto must be tcp or udp")
		}
		pt := Port{n, proto}
		if !seen[pt] {
			seen[pt] = true
			out = append(out, pt)
		}
	}
	return out, nil
}

func parseCreds(v any) ([]Credential, error) {
	if v == nil {
		return nil, nil
	}
	l, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("snmp must be a list")
	}
	if len(l) > maxCredentials {
		return nil, fmt.Errorf("at most %d SNMP credentials", maxCredentials)
	}
	var out []Credential
	for i, e := range l {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("snmp credential %d must be an object", i+1)
		}
		c := Credential{ID: m["id"]}
		switch id := m["id"].(type) {
		case string:
			if id == "" || len(id) > 64 {
				return nil, fmt.Errorf("snmp credential %d: id must be 1-64 characters", i+1)
			}
		case float64:
		default:
			return nil, fmt.Errorf("snmp credential %d: id is required", i+1)
		}
		str := func(k string) string { s, _ := m[k].(string); return s }
		c.Version = strings.ToLower(str("version"))
		switch c.Version {
		case "v2c":
			c.Community = str("community")
			if c.Community == "" || len(c.Community) > maxSecretLen {
				return nil, fmt.Errorf("snmp credential %d: community is required (at most %d characters)", i+1, maxSecretLen)
			}
		case "v3":
			c.Username, c.Level = str("username"), str("level")
			c.AuthProto, c.PrivProto = strings.ToUpper(str("auth_proto")), strings.ToUpper(str("priv_proto"))
			c.AuthPassword, c.PrivPassword = str("auth_password"), str("priv_password")
			if c.Username == "" || len(c.Username) > 64 {
				return nil, fmt.Errorf("snmp credential %d: username is required", i+1)
			}
			switch c.AuthProto {
			case "SHA", "SHA256", "SHA512":
			default:
				return nil, fmt.Errorf("snmp credential %d: auth_proto must be SHA, SHA256 or SHA512", i+1)
			}
			if len(c.AuthPassword) < 8 || len(c.AuthPassword) > maxSecretLen {
				return nil, fmt.Errorf("snmp credential %d: auth_password must be 8-%d characters", i+1, maxSecretLen)
			}
			switch c.Level {
			case "authPriv":
				if c.PrivProto != "AES128" && c.PrivProto != "AES256" {
					return nil, fmt.Errorf("snmp credential %d: authPriv needs priv_proto AES128 or AES256", i+1)
				}
				if len(c.PrivPassword) < 8 || len(c.PrivPassword) > maxSecretLen {
					return nil, fmt.Errorf("snmp credential %d: priv_password must be 8-%d characters", i+1, maxSecretLen)
				}
			case "authNoPriv":
				c.PrivProto, c.PrivPassword = "NONE", ""
			default:
				return nil, fmt.Errorf("snmp credential %d: level must be authPriv or authNoPriv", i+1)
			}
		default:
			return nil, fmt.Errorf("snmp credential %d: version must be v3 or v2c", i+1)
		}
		out = append(out, c)
	}
	return out, nil
}
