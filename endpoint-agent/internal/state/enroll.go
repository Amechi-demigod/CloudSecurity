package state

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// EnrollFileName is the pending-enrollment document an installer (MSI custom
// action, macOS pkg postinstall, MDM script) leaves in the state directory.
// The service enrolls with it on start and then deletes it, so the
// enrollment token only lives on disk until the device is enrolled.
const EnrollFileName = "enroll.json"

// EnrollConfigVersion is the only supported enroll.json format.
const EnrollConfigVersion = 1

// ErrNoEnrollConfig is returned by LoadEnrollConfig when no enroll.json exists.
var ErrNoEnrollConfig = errors.New("no pending enrollment configuration")

// MaxEnrollConfigBytes caps enroll.json (the CA bundle is the only large part).
const MaxEnrollConfigBytes = 256 << 10

var tokenRe = regexp.MustCompile(`^cne_[A-Za-z0-9_-]{8,124}$`)

// EnrollConfig is the content of enroll.json.
type EnrollConfig struct {
	Version   int    `json:"version"`
	ServerURL string `json:"server_url"`
	Token     string `json:"token"`
	// PEM bundle of the private CA that issued the server certificate; empty
	// when the server's certificate is publicly (or already machine-) trusted.
	CAPEM string `json:"ca_pem,omitempty"`
}

// EnrollFile is the full path of enroll.json.
func (p Paths) EnrollFile() string { return filepath.Join(p.StateDir, EnrollFileName) }

// Validate normalises and checks the configuration (https only, token shape, CA parses).
func (c *EnrollConfig) Validate() error {
	if c.Version == 0 {
		c.Version = EnrollConfigVersion
	}
	if c.Version != EnrollConfigVersion {
		return fmt.Errorf("unsupported enrollment config version %d", c.Version)
	}
	server, err := ValidateServerURL(c.ServerURL, false)
	if err != nil {
		return err
	}
	c.ServerURL = server
	c.Token = strings.TrimSpace(c.Token)
	if !tokenRe.MatchString(c.Token) {
		return errors.New("the enrollment token is missing or malformed (expected cne_...)")
	}
	c.CAPEM = strings.TrimSpace(c.CAPEM)
	if c.CAPEM != "" {
		if _, err := ParseCABundle([]byte(c.CAPEM)); err != nil {
			return err
		}
		c.CAPEM += "\n"
	}
	return nil
}

// ParseCABundle checks that b holds at least one PEM certificate and nothing else unparsable.
func ParseCABundle(b []byte) (int, error) {
	n := 0
	rest := bytes.TrimSpace(b)
	for len(rest) > 0 {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			return 0, fmt.Errorf("CA bundle contains a %q block; only certificates are allowed", blk.Type)
		}
		if _, err := x509.ParseCertificate(blk.Bytes); err != nil {
			return 0, fmt.Errorf("CA bundle: %w", err)
		}
		n++
		rest = bytes.TrimSpace(rest)
	}
	if n == 0 {
		return 0, errors.New("CA bundle contains no PEM certificates")
	}
	return n, nil
}

// DecodeCAB64 decodes the MSI property CNAPP_CA_B64: base64 of a PEM bundle,
// or base64 of a single DER certificate (converted to PEM).
func DecodeCAB64(s string) (string, error) {
	s = strings.Join(strings.Fields(s), "")
	if s == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		if raw, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "=")); err != nil {
			return "", fmt.Errorf("CA certificate is not valid base64: %w", err)
		}
	}
	if !bytes.Contains(raw, []byte("-----BEGIN")) {
		if _, err := x509.ParseCertificate(raw); err != nil {
			return "", fmt.Errorf("CA certificate (DER): %w", err)
		}
		raw = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
	}
	return string(raw), nil
}

// ParseEnrollConfig parses and validates an enroll.json document.
func ParseEnrollConfig(b []byte) (*EnrollConfig, error) {
	if len(b) > MaxEnrollConfigBytes {
		return nil, errors.New("enrollment config is too large")
	}
	var c EnrollConfig
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("enrollment config is not valid JSON: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// SaveEnrollConfig validates c and writes enroll.json with the same
// protection as state.json (SYSTEM/Administrators or root only).
func SaveEnrollConfig(p Paths, c *EnrollConfig) error {
	if err := c.Validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return writeSecure(p.StateDir, p.EnrollFile(), b)
}

// LoadEnrollConfig reads enroll.json. Outside of --home (test) mode the file
// must be owned by root / SYSTEM / Administrators and not writable by others,
// so an unprivileged user cannot point the agent at another server.
func LoadEnrollConfig(p Paths) (*EnrollConfig, error) {
	f := p.EnrollFile()
	info, err := os.Lstat(f)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoEnrollConfig
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", f)
	}
	if !p.Custom {
		if err := checkPrivilegedOwner(f); err != nil {
			return nil, fmt.Errorf("refusing %s: %w", f, err)
		}
	}
	b, err := os.ReadFile(f)
	if err != nil {
		return nil, err
	}
	return ParseEnrollConfig(b)
}

// RemoveEnrollConfig overwrites and deletes enroll.json (best effort wipe of the token).
func RemoveEnrollConfig(p Paths) error {
	f := p.EnrollFile()
	if info, err := os.Stat(f); err == nil && info.Mode().IsRegular() {
		if w, err := os.OpenFile(f, os.O_WRONLY, 0); err == nil {
			_, _ = w.Write(make([]byte, info.Size()))
			_ = w.Sync()
			_ = w.Close()
		}
	}
	if err := os.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// MSI preset (property CNAPP_PRESET): a fixed-length value the CNAPP server
// overwrites in a copy of the generic MSI for a pre-configured download.
const (
	presetUnset = "CNAPPPRESET:UNSET"
	presetV1    = "CNAPPPRESET:v1:"
)

// DecodePreset returns the enrollment config carried by an MSI preset, or nil
// for the generic MSI's placeholder (or an empty value).
func DecodePreset(s string) (*EnrollConfig, error) {
	s = strings.TrimRight(strings.TrimSpace(s), ".")
	switch {
	case s == "" || strings.HasPrefix(s, presetUnset):
		return nil, nil
	case strings.HasPrefix(s, presetV1):
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, presetV1))
		if err != nil {
			return nil, fmt.Errorf("MSI enrollment preset is not valid base64: %w", err)
		}
		return ParseEnrollConfig(raw)
	default:
		return nil, errors.New("unrecognized MSI enrollment preset")
	}
}
