// Package scripts runs approved device scripts: only scripts from a bundle
// whose manifest is signed by a script-signing key compiled into this agent
// (trusted_keys.txt, separate from the agent release key), whose bytes match
// the SHA-256 in that signed manifest, with parameters validated against the
// signed, typed schema. Values reach the script only as environment variables
// CNAPP_PARAM_<NAME>; nothing from the server is put on a command line or into
// the script text. See docs/DEVICE_SCRIPTS.md and
// docs/ADR-0001-signed-device-scripts.md.
//
// The manifest rules mirror backend/app/script_manifest.py.
package scripts

import (
	"bytes"
	"crypto/ed25519"
	_ "embed" // trusted_keys.txt
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/update"
)

// SignatureContext is prepended to the payload before signing (domain
// separation: an agent-update signature never verifies as a script manifest).
const SignatureContext = "cnapp-device-scripts-manifest-v1\x00"

// Product is the only product name accepted.
const Product = "cnapp-device-scripts"

// Limits (same as the server).
const (
	MaxManifestBytes = 256 << 10
	MaxScriptBytes   = 64 << 10
	MaxStringLength  = 256
	maxClockSkew     = 24 * time.Hour
)

//go:embed trusted_keys.txt
var trustedKeysFile string

// ExtraTrustedKeys adds script-signing keys at build time (tests only):
//
//	-ldflags "-X github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/scripts.ExtraTrustedKeys=<id> <b64>"
var ExtraTrustedKeys string

// BuiltinKeys returns the script-signing keys compiled into this binary.
func BuiltinKeys() ([]update.TrustedKey, error) {
	keys, err := update.ParseKeys(trustedKeysFile)
	if err != nil {
		return nil, fmt.Errorf("embedded scripts/trusted_keys.txt: %w", err)
	}
	extra, err := update.ParseKeys(ExtraTrustedKeys)
	if err != nil {
		return nil, fmt.Errorf("scripts.ExtraTrustedKeys: %w", err)
	}
	return append(keys, extra...), nil
}

// Errors.
var (
	ErrMalformed    = errors.New("malformed script manifest")
	ErrNoTrustedKey = errors.New("script manifest is not signed by a trusted script-signing key")
	ErrBadSignature = errors.New("script manifest signature is invalid")
	ErrExpired      = errors.New("script manifest expired")
	ErrParam        = errors.New("invalid script parameter")
)

// Param is one typed parameter of a script.
type Param struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"` // string | enum | int | bool
	Description string   `json:"description,omitempty"`
	Required    *bool    `json:"required,omitempty"`
	Default     any      `json:"default,omitempty"`
	Pattern     string   `json:"pattern,omitempty"`
	MaxLength   int      `json:"max_length,omitempty"`
	Values      []string `json:"values,omitempty"`
	Min         *int64   `json:"min,omitempty"`
	Max         *int64   `json:"max,omitempty"`

	re *regexp.Regexp
}

// Entry is one script in the signed manifest.
type Entry struct {
	Name           string  `json:"name"`
	Description    string  `json:"description"`
	Platform       string  `json:"platform"`    // windows | macos
	Interpreter    string  `json:"interpreter"` // powershell | zsh | bash
	File           string  `json:"file"`
	TimeoutSeconds int     `json:"timeout_seconds"`
	Risk           string  `json:"risk"`
	Parameters     []Param `json:"parameters"`
	SHA256         string  `json:"sha256"`
	Size           int64   `json:"size"`
}

// Manifest is the signed bundle description.
type Manifest struct {
	Schema     int       `json:"schema"`
	Product    string    `json:"product"`
	Version    string    `json:"version"`
	ReleasedAt time.Time `json:"released_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Notes      string    `json:"notes,omitempty"`
	Scripts    []Entry   `json:"scripts"`

	KeyID string `json:"-"`
}

var (
	nameRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,63}$`)
	fileRe      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,59}\.(ps1|sh|zsh)$`)
	paramNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	enumValueRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	shaRe       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	intRe       = regexp.MustCompile(`^-?[0-9]{1,10}$`)
	interps     = map[string][]string{"windows": {"powershell"}, "macos": {"zsh", "bash"}}
	extensions  = map[string][]string{"powershell": {".ps1"}, "zsh": {".zsh", ".sh"}, "bash": {".sh"}}
)

// Verify checks the envelope signature with the trusted keys and validates the manifest.
func Verify(envelope []byte, keys []update.TrustedKey, now time.Time) (*Manifest, error) {
	if len(envelope) > MaxManifestBytes {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrMalformed, MaxManifestBytes)
	}
	var env update.Envelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil || len(payload) == 0 {
		return nil, fmt.Errorf("%w: payload is not base64", ErrMalformed)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: this agent build trusts no script-signing keys (scripts disabled)", ErrNoTrustedKey)
	}
	msg := append([]byte(SignatureContext), payload...)
	keyID, sawTrusted := "", false
	for _, s := range env.Signatures {
		for _, k := range keys {
			if s.KeyID != k.ID {
				continue
			}
			sawTrusted = true
			sig, err := base64.StdEncoding.DecodeString(s.Sig)
			if err == nil && len(sig) == ed25519.SignatureSize && ed25519.Verify(k.Pub, msg, sig) {
				keyID = k.ID
			}
		}
		if keyID != "" {
			break
		}
	}
	if keyID == "" {
		if !sawTrusted {
			return nil, ErrNoTrustedKey
		}
		return nil, ErrBadSignature
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(payload))
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	m.KeyID = keyID
	if err := m.validate(now); err != nil {
		return nil, err
	}
	return &m, nil
}

func (m *Manifest) validate(now time.Time) error {
	if m.Schema != 1 || m.Product != Product {
		return fmt.Errorf("%w: not a schema-1 %s manifest", ErrMalformed, Product)
	}
	if _, err := update.ParseSemver(m.Version); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if m.ExpiresAt.IsZero() || m.ReleasedAt.IsZero() || !m.ExpiresAt.After(m.ReleasedAt) {
		return fmt.Errorf("%w: released_at/expires_at missing or inconsistent", ErrMalformed)
	}
	if !now.Before(m.ExpiresAt) {
		return fmt.Errorf("%w at %s", ErrExpired, m.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if m.ReleasedAt.After(now.Add(maxClockSkew)) {
		return fmt.Errorf("%w: released_at is in the future", ErrMalformed)
	}
	if len(m.Scripts) == 0 {
		return fmt.Errorf("%w: no scripts", ErrMalformed)
	}
	seen := map[string]bool{}
	for i := range m.Scripts {
		e := &m.Scripts[i]
		if err := e.validate(); err != nil {
			return fmt.Errorf("%w: script %q: %v", ErrMalformed, e.Name, err)
		}
		if seen[e.Name] {
			return fmt.Errorf("%w: duplicate script %q", ErrMalformed, e.Name)
		}
		seen[e.Name] = true
	}
	return nil
}

func (e *Entry) validate() error {
	if !nameRe.MatchString(e.Name) {
		return errors.New("bad name")
	}
	ok := false
	for _, i := range interps[e.Platform] {
		ok = ok || i == e.Interpreter
	}
	if !ok {
		return fmt.Errorf("interpreter %q not allowed for platform %q", e.Interpreter, e.Platform)
	}
	extOK := false
	for _, x := range extensions[e.Interpreter] {
		extOK = extOK || strings.HasSuffix(e.File, x)
	}
	if !fileRe.MatchString(e.File) || !extOK {
		return fmt.Errorf("bad file name %q", e.File)
	}
	if e.TimeoutSeconds < 5 || e.TimeoutSeconds > 3600 {
		return errors.New("timeout_seconds out of range")
	}
	if e.Risk != "low" && e.Risk != "medium" && e.Risk != "high" {
		return errors.New("bad risk")
	}
	if b, err := hex.DecodeString(e.SHA256); err != nil || len(b) != 32 || !shaRe.MatchString(e.SHA256) {
		return errors.New("bad sha256")
	}
	if e.Size <= 0 || e.Size > MaxScriptBytes {
		return errors.New("size out of range")
	}
	names := map[string]bool{}
	for i := range e.Parameters {
		p := &e.Parameters[i]
		if err := p.compile(); err != nil {
			return fmt.Errorf("parameter %q: %v", p.Name, err)
		}
		if names[p.Name] {
			return fmt.Errorf("duplicate parameter %q", p.Name)
		}
		names[p.Name] = true
	}
	return nil
}

func (p *Param) compile() error {
	if !paramNameRe.MatchString(p.Name) {
		return errors.New("bad name")
	}
	switch p.Type {
	case "string":
		if !strings.HasPrefix(p.Pattern, "^") || !strings.HasSuffix(p.Pattern, "$") || len(p.Pattern) > 200 {
			return errors.New("string parameters need an anchored pattern")
		}
		inner := strings.TrimSuffix(strings.TrimPrefix(p.Pattern, "^"), "$")
		re, err := regexp.Compile("^(?:" + inner + ")$")
		if err != nil {
			return err
		}
		p.re = re
		if p.MaxLength == 0 {
			p.MaxLength = MaxStringLength
		}
		if p.MaxLength < 1 || p.MaxLength > MaxStringLength {
			return errors.New("max_length out of range")
		}
	case "enum":
		if len(p.Values) == 0 {
			return errors.New("enum without values")
		}
		for _, v := range p.Values {
			if !enumValueRe.MatchString(v) {
				return fmt.Errorf("bad enum value %q", v)
			}
		}
	case "int":
		if p.Min == nil || p.Max == nil || *p.Min > *p.Max {
			return errors.New("int parameters need min <= max")
		}
	case "bool":
	default:
		return fmt.Errorf("unknown type %q", p.Type)
	}
	return nil
}

func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// coerce validates one value and returns the string the script receives.
func (p *Param) coerce(v any) (string, error) {
	switch p.Type {
	case "bool":
		b, ok := v.(bool)
		if !ok {
			return "", errors.New("must be true or false")
		}
		return strconv.FormatBool(b), nil
	case "int":
		var n int64
		switch x := v.(type) {
		case float64:
			if x != math.Trunc(x) || math.Abs(x) > 1<<31 {
				return "", errors.New("must be an integer")
			}
			n = int64(x)
		case string:
			if !intRe.MatchString(x) {
				return "", errors.New("must be an integer")
			}
			n, _ = strconv.ParseInt(x, 10, 64)
		default:
			return "", errors.New("must be an integer")
		}
		if n < *p.Min || n > *p.Max {
			return "", fmt.Errorf("must be between %d and %d", *p.Min, *p.Max)
		}
		return strconv.FormatInt(n, 10), nil
	}
	s, ok := v.(string)
	if !ok {
		return "", errors.New("must be a string")
	}
	if p.Type == "enum" {
		for _, x := range p.Values {
			if x == s {
				return s, nil
			}
		}
		return "", fmt.Errorf("must be one of %s", strings.Join(p.Values, ", "))
	}
	if hasControl(s) || !utf8.ValidString(s) {
		return "", errors.New("must not contain control characters")
	}
	if utf8.RuneCountInString(s) > p.MaxLength {
		return "", fmt.Errorf("must be at most %d characters", p.MaxLength)
	}
	if !p.re.MatchString(s) {
		return "", fmt.Errorf("does not match %s", p.Pattern)
	}
	return s, nil
}

// ValidateParams checks run parameters against the signed schema and returns
// the environment variables for the script (CNAPP_PARAM_<NAME>=value).
// Unknown parameters are refused; defaults are applied.
func (e *Entry) ValidateParams(values map[string]any) ([]string, error) {
	known := map[string]bool{}
	var env []string
	for i := range e.Parameters {
		p := &e.Parameters[i]
		known[p.Name] = true
		v, ok := values[p.Name]
		if !ok || v == nil {
			switch {
			case p.Default != nil:
				v = p.Default
			case p.Required == nil || *p.Required:
				return nil, fmt.Errorf("%w: %s is required", ErrParam, p.Name)
			default:
				continue
			}
		}
		s, err := p.coerce(v)
		if err != nil {
			return nil, fmt.Errorf("%w: %s %v", ErrParam, p.Name, err)
		}
		env = append(env, "CNAPP_PARAM_"+strings.ToUpper(p.Name)+"="+s)
	}
	for k := range values {
		if !known[k] {
			return nil, fmt.Errorf("%w: unknown parameter %q", ErrParam, k)
		}
	}
	return env, nil
}
