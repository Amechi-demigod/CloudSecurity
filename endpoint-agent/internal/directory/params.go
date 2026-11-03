// Package directory implements the directory_sync command: a read-only,
// paged LDAP export of computer and user objects from on-prem Active
// Directory, streamed to the server in gzip-compressed JSON batches
// (docs/DIRECTORY_DISCOVERY.md).
//
// Security model:
//   - read-only: only Bind and Search are ever sent; no modify/add/delete;
//   - the filters and attribute lists are fixed in code, the server only
//     chooses domain, DCs, base DNs and scopes;
//   - transport is always TLS (LDAPS or StartTLS) with certificate
//     verification against the system roots (+ an optional pinned CA);
//     plain / unsigned LDAP is never used and a password is never sent
//     outside TLS;
//   - authentication is the computer account via Kerberos/SSPI (Windows; no
//     secret on the device) or a read-only service account (simple bind over
//     TLS) whose password only lives in memory for the duration of the sync;
//   - the password and the single-use upload token never appear in logs,
//     command output or error messages.
package directory

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
)

// CommandType is the command this package implements.
const CommandType = "directory_sync"

// Scopes.
const (
	ScopeComputers = "computers"
	ScopeUsers     = "users"
)

// Transport security and authentication modes.
const (
	SecurityLDAPS    = "ldaps"
	SecurityStartTLS = "starttls"
	AuthKerberos     = "kerberos"
	AuthSimple       = "simple"
)

// UploadPrefix is the only server path batches are posted to.
const UploadPrefix = "/api/agent/directory/runs/"

// Limits (mirrored by the server).
const (
	MaxServers    = 10
	MaxBaseDNs    = 10
	MaxDNLen      = 1024
	MaxCAPEM      = 16384
	MinPageSize   = 100
	MaxPageSize   = 1000
	MinBatchSize  = 100
	MaxBatchSize  = 5000
	MaxObjectsCap = 2_000_000
	MinTimeout    = 60
	MaxTimeout    = 21600
)

// AllowedParams lists every parameter a directory_sync command may carry.
var AllowedParams = []string{"source_id", "run_id", "domain", "servers", "port", "security", "base_dns", "scopes",
	"page_size", "batch_size", "max_objects", "timeout_seconds", "auth", "ca_pem", "test", "upload_path",
	"upload_token", "credential"}

var (
	idRe     = regexp.MustCompile(`^[0-9a-f]{32}$`)
	domainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62})(\.[a-z0-9]([a-z0-9-]{0,62}))*$`)
	hostRe   = regexp.MustCompile(`^[A-Za-z0-9.:-]{1,253}$`)
	tokenRe  = regexp.MustCompile(`^[A-Za-z0-9_-]{20,128}$`)
)

// Params is a validated directory_sync command.
type Params struct {
	SourceID    string
	RunID       string
	Domain      string
	Servers     []string
	Port        int
	Security    string
	BaseDNs     []string
	Scopes      []string
	PageSize    int
	BatchSize   int
	MaxObjects  int
	Timeout     time.Duration
	Auth        string
	CAPEM       string
	Test        bool
	UploadPath  string
	UploadToken string
	Username    string
	Password    string
}

// String never prints the credential or the upload token.
func (p *Params) String() string {
	return fmt.Sprintf("directory_sync(run=%s domain=%s security=%s auth=%s scopes=%v)", p.RunID, p.Domain,
		p.Security, p.Auth, p.Scopes)
}

// Secrets returns the values that must never appear in output.
func (p *Params) Secrets() []string {
	return []string{p.Password, p.UploadToken}
}

// SearchBases are the configured base DNs, or the domain's naming context.
func (p *Params) SearchBases() []string {
	if len(p.BaseDNs) > 0 {
		return p.BaseDNs
	}
	return []string{DomainToDN(p.Domain)}
}

// DomainToDN turns corp.example.com into DC=corp,DC=example,DC=com.
func DomainToDN(domain string) string {
	parts := strings.Split(domain, ".")
	for i, s := range parts {
		parts[i] = "DC=" + s
	}
	return strings.Join(parts, ",")
}

// KerberosSupported reports whether this build can bind with the computer
// account (SSPI, Windows only).
func KerberosSupported() bool { return kerberosSupported }

func str(p map[string]any, k string, required bool) (string, error) {
	v, ok := p[k]
	if !ok || v == nil {
		if required {
			return "", fmt.Errorf("%s is required", k)
		}
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", k)
	}
	return strings.TrimSpace(s), nil
}

func intParam(p map[string]any, k string, def, lo, hi int) (int, error) {
	v, ok := p[k]
	if !ok || v == nil {
		return def, nil
	}
	f, ok := v.(float64)
	if !ok || f != math.Trunc(f) || f < float64(lo) || f > float64(hi) {
		return 0, fmt.Errorf("%s must be an integer between %d and %d", k, lo, hi)
	}
	return int(f), nil
}

func strList(p map[string]any, k string, max int) ([]string, error) {
	v, ok := p[k]
	if !ok || v == nil {
		return nil, nil
	}
	arr, ok := v.([]any)
	if !ok || len(arr) > max {
		return nil, fmt.Errorf("%s must be a list of at most %d strings", k, max)
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		s, ok := x.(string)
		if !ok {
			return nil, fmt.Errorf("%s must be a list of strings", k)
		}
		out = append(out, strings.TrimSpace(s))
	}
	return out, nil
}

func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// ParseParams validates a directory_sync command's parameters. Errors name
// the offending parameter but never echo a credential or token value.
func ParseParams(raw map[string]any) (*Params, error) {
	allowed := map[string]bool{}
	for _, k := range AllowedParams {
		allowed[k] = true
	}
	for k := range raw {
		if !allowed[k] {
			return nil, fmt.Errorf("unexpected parameter %q", k)
		}
	}
	p := &Params{}
	var err error
	if p.SourceID, err = str(raw, "source_id", true); err != nil {
		return nil, err
	}
	if p.RunID, err = str(raw, "run_id", true); err != nil {
		return nil, err
	}
	if !idRe.MatchString(p.SourceID) || !idRe.MatchString(p.RunID) {
		return nil, errors.New("source_id and run_id must be 32 lower-case hex characters")
	}
	if p.Domain, err = str(raw, "domain", true); err != nil {
		return nil, err
	}
	p.Domain = strings.TrimSuffix(strings.ToLower(p.Domain), ".")
	if len(p.Domain) > 253 || !domainRe.MatchString(p.Domain) {
		return nil, errors.New("domain must be a DNS domain name such as corp.example.com")
	}
	if p.Servers, err = strList(raw, "servers", MaxServers); err != nil {
		return nil, err
	}
	for _, h := range p.Servers {
		if !hostRe.MatchString(h) || strings.HasPrefix(h, "-") {
			return nil, errors.New("servers must be host names or IP addresses (letters, digits, '.', ':', '-')")
		}
	}
	if p.Security, err = str(raw, "security", false); err != nil {
		return nil, err
	}
	if p.Security == "" {
		p.Security = SecurityLDAPS
	}
	if p.Security != SecurityLDAPS && p.Security != SecurityStartTLS {
		return nil, errors.New("security must be ldaps or starttls (plain LDAP is never used)")
	}
	defPort := 636
	if p.Security == SecurityStartTLS {
		defPort = 389
	}
	if p.Port, err = intParam(raw, "port", defPort, 1, 65535); err != nil {
		return nil, err
	}
	if p.Port == 389 && p.Security != SecurityStartTLS {
		return nil, errors.New("port 389 requires security starttls")
	}
	if p.BaseDNs, err = strList(raw, "base_dns", MaxBaseDNs); err != nil {
		return nil, err
	}
	for _, dn := range p.BaseDNs {
		if dn == "" || len(dn) > MaxDNLen || !strings.Contains(dn, "=") || hasControl(dn) {
			return nil, fmt.Errorf("base_dns entries must be distinguished names of at most %d characters", MaxDNLen)
		}
	}
	if p.Scopes, err = strList(raw, "scopes", 2); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, s := range p.Scopes {
		if (s != ScopeComputers && s != ScopeUsers) || seen[s] {
			return nil, errors.New("scopes must be computers and/or users")
		}
		seen[s] = true
	}
	if len(p.Scopes) == 0 {
		return nil, errors.New("scopes must name computers and/or users")
	}
	if p.PageSize, err = intParam(raw, "page_size", MaxPageSize, MinPageSize, MaxPageSize); err != nil {
		return nil, err
	}
	if p.BatchSize, err = intParam(raw, "batch_size", 2000, MinBatchSize, MaxBatchSize); err != nil {
		return nil, err
	}
	if p.MaxObjects, err = intParam(raw, "max_objects", 500_000, 1, MaxObjectsCap); err != nil {
		return nil, err
	}
	secs, err := intParam(raw, "timeout_seconds", 3600, MinTimeout, MaxTimeout)
	if err != nil {
		return nil, err
	}
	p.Timeout = time.Duration(secs) * time.Second
	if p.Auth, err = str(raw, "auth", true); err != nil {
		return nil, err
	}
	switch p.Auth {
	case AuthKerberos:
		if !kerberosSupported {
			return nil, errors.New("auth kerberos (computer account) needs a domain-joined Windows collector; use a service account on this device")
		}
		if _, ok := raw["credential"]; ok && raw["credential"] != nil {
			return nil, errors.New("credential must not be sent with auth kerberos")
		}
	case AuthSimple:
		cred, ok := raw["credential"].(map[string]any)
		if !ok || len(cred) != 2 {
			return nil, errors.New("auth simple requires credential {username, password}")
		}
		u, uok := cred["username"].(string)
		pw, pok := cred["password"].(string)
		u = strings.TrimSpace(u)
		if !uok || !pok || u == "" || pw == "" || len(u) > 256 || len(pw) > 1024 || hasControl(u) ||
			strings.ContainsRune(pw, 0) {
			return nil, errors.New("credential must have a username (<=256) and a password (<=1024)")
		}
		p.Username, p.Password = u, pw
	default:
		return nil, errors.New("auth must be kerberos or simple")
	}
	if p.CAPEM, err = str(raw, "ca_pem", false); err != nil {
		return nil, err
	}
	if p.CAPEM != "" {
		if len(p.CAPEM) > MaxCAPEM {
			return nil, fmt.Errorf("ca_pem is larger than %d bytes", MaxCAPEM)
		}
		if _, err := CertPool(p.CAPEM); err != nil {
			return nil, err
		}
	}
	if v, ok := raw["test"]; ok && v != nil {
		b, ok := v.(bool)
		if !ok {
			return nil, errors.New("test must be a boolean")
		}
		p.Test = b
	}
	if p.UploadPath, err = str(raw, "upload_path", true); err != nil {
		return nil, err
	}
	if err := ValidUploadPath(p.UploadPath); err != nil {
		return nil, err
	}
	if p.UploadToken, err = str(raw, "upload_token", true); err != nil {
		return nil, err
	}
	if !tokenRe.MatchString(p.UploadToken) {
		return nil, errors.New("upload_token is malformed")
	}
	return p, nil
}

// ValidUploadPath accepts only /api/agent/directory/runs/... on the enrolled server.
func ValidUploadPath(path string) error {
	if !strings.HasPrefix(path, UploadPrefix) || len(path) > 256 || strings.Contains(path, "..") ||
		strings.ContainsAny(path, "?#\\ ") || hasControl(path) {
		return fmt.Errorf("upload_path must start with %s", UploadPrefix)
	}
	return nil
}

// CertPool parses extra PEM CA certificates.
func CertPool(pemData string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	rest := []byte(pemData)
	n := 0
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, errors.New("ca_pem contains an invalid certificate")
		}
		pool.AddCert(c)
		n++
	}
	if n == 0 {
		return nil, errors.New("ca_pem contains no PEM certificate")
	}
	return pool, nil
}
