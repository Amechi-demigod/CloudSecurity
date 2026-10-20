// Package update implements signed agent self-update.
//
// Trust model: a release manifest is signed with an Ed25519 release key that
// is held outside the CNAPP server (a GitHub Actions secret or offline). The
// agent only trusts the public keys compiled into it (trusted_keys.txt). The
// server merely chooses which already-signed release a device should run and
// serves the bytes; a compromised server can neither forge a manifest nor
// alter an artifact (its SHA-256 and size are inside the signed manifest),
// nor downgrade an agent (anti-rollback), nor replay an expired manifest.
// The agent never runs scripts from the server: it only swaps its own binary.
package update

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SignatureContext is prepended to the payload before signing (domain separation).
const SignatureContext = "cnapp-agent-update-manifest-v1\x00"

// Product is the only product name the agent accepts.
const Product = "cnapp-agent"

// Limits.
const (
	MaxManifestBytes = 64 << 10
	MaxArtifactBytes = 200 << 20
	maxClockSkew     = 24 * time.Hour
)

// Errors (wrapped with details).
var (
	ErrMalformed       = errors.New("malformed manifest")
	ErrNoTrustedKey    = errors.New("manifest is not signed by a trusted key")
	ErrBadSignature    = errors.New("manifest signature is invalid")
	ErrExpired         = errors.New("manifest expired")
	ErrNotYetValid     = errors.New("manifest is not valid yet")
	ErrNoArtifact      = errors.New("release has no artifact for this platform")
	ErrDowngrade       = errors.New("downgrade refused (anti-rollback)")
	ErrSameVersion     = errors.New("already running this version")
	ErrTooOld          = errors.New("current version is below the release's minimum supported version")
	ErrHashMismatch    = errors.New("artifact SHA-256 does not match the signed manifest")
	ErrSizeMismatch    = errors.New("artifact size does not match the signed manifest")
	ErrVersionMismatch = errors.New("offered version does not match the signed manifest")
)

// Envelope is the transport form: the exact signed bytes plus signatures.
type Envelope struct {
	Payload    string      `json:"payload"` // base64 of the manifest JSON
	Signatures []Signature `json:"signatures"`
}

// Signature is one Ed25519 signature over SignatureContext + payload bytes.
type Signature struct {
	KeyID string `json:"key_id"`
	Sig   string `json:"sig"` // base64
}

// Artifact is one platform binary of a release.
type Artifact struct {
	OS     string `json:"os"`   // GOOS: windows | darwin
	Arch   string `json:"arch"` // GOARCH: amd64 | arm64
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Manifest is the signed release description.
type Manifest struct {
	Schema              int        `json:"schema"`
	Product             string     `json:"product"`
	Version             string     `json:"version"`
	ReleasedAt          time.Time  `json:"released_at"`
	ExpiresAt           time.Time  `json:"expires_at"`
	MinSupportedVersion string     `json:"min_supported_version"`
	RollbackAllowedFrom []string   `json:"rollback_allowed_from,omitempty"`
	Artifacts           []Artifact `json:"artifacts"`
	Notes               string     `json:"notes,omitempty"`

	KeyID string `json:"-"` // the trusted key that verified it
}

// Verify checks the envelope's signature against the trusted keys and returns
// the manifest. It does not apply version policy (see Check).
func Verify(envelope []byte, keys []TrustedKey, now time.Time) (*Manifest, error) {
	if len(envelope) > MaxManifestBytes {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrMalformed, MaxManifestBytes)
	}
	var env Envelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil || len(payload) == 0 {
		return nil, fmt.Errorf("%w: payload is not base64", ErrMalformed)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: this agent build trusts no release keys (auto-update disabled)", ErrNoTrustedKey)
	}
	msg := append([]byte(SignatureContext), payload...)
	keyID := ""
	sawTrusted := false
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
		ids := make([]string, 0, len(env.Signatures))
		for _, s := range env.Signatures {
			ids = append(ids, s.KeyID)
		}
		if !sawTrusted {
			return nil, fmt.Errorf("%w (signed by %s)", ErrNoTrustedKey, strings.Join(ids, ", "))
		}
		return nil, fmt.Errorf("%w (key %s)", ErrBadSignature, strings.Join(ids, ", "))
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
	if m.Schema != 1 {
		return fmt.Errorf("%w: unsupported schema %d", ErrMalformed, m.Schema)
	}
	if m.Product != Product {
		return fmt.Errorf("%w: product %q is not %q", ErrMalformed, m.Product, Product)
	}
	if _, err := ParseSemver(m.Version); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if m.MinSupportedVersion != "" {
		if _, err := ParseSemver(m.MinSupportedVersion); err != nil {
			return fmt.Errorf("%w: min_supported_version: %v", ErrMalformed, err)
		}
	}
	for _, v := range m.RollbackAllowedFrom {
		if _, err := ParseSemver(v); err != nil {
			return fmt.Errorf("%w: rollback_allowed_from: %v", ErrMalformed, err)
		}
	}
	if m.ExpiresAt.IsZero() || m.ReleasedAt.IsZero() || !m.ExpiresAt.After(m.ReleasedAt) {
		return fmt.Errorf("%w: released_at/expires_at missing or inconsistent", ErrMalformed)
	}
	if !now.Before(m.ExpiresAt) {
		return fmt.Errorf("%w at %s", ErrExpired, m.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if m.ReleasedAt.After(now.Add(maxClockSkew)) {
		return fmt.Errorf("%w (released_at %s)", ErrNotYetValid, m.ReleasedAt.UTC().Format(time.RFC3339))
	}
	if len(m.Artifacts) == 0 {
		return fmt.Errorf("%w: no artifacts", ErrMalformed)
	}
	seen := map[string]bool{}
	for _, a := range m.Artifacts {
		if a.OS == "" || a.Arch == "" || seen[a.OS+"/"+a.Arch] {
			return fmt.Errorf("%w: artifact platform missing or duplicated (%s/%s)", ErrMalformed, a.OS, a.Arch)
		}
		seen[a.OS+"/"+a.Arch] = true
		if b, err := hex.DecodeString(a.SHA256); err != nil || len(b) != 32 || a.SHA256 != strings.ToLower(a.SHA256) {
			return fmt.Errorf("%w: artifact %s/%s sha256 is not 64 lowercase hex characters", ErrMalformed, a.OS, a.Arch)
		}
		if a.Size <= 0 || a.Size > MaxArtifactBytes {
			return fmt.Errorf("%w: artifact %s/%s size %d out of range", ErrMalformed, a.OS, a.Arch, a.Size)
		}
	}
	return nil
}

// ArtifactFor returns the artifact for goos/goarch.
func (m *Manifest) ArtifactFor(goos, goarch string) (*Artifact, error) {
	for i := range m.Artifacts {
		if m.Artifacts[i].OS == goos && m.Artifacts[i].Arch == goarch {
			return &m.Artifacts[i], nil
		}
	}
	return nil, fmt.Errorf("%w (%s/%s)", ErrNoArtifact, goos, goarch)
}

// Check applies the version policy for an agent running `current` on
// goos/goarch and returns the artifact to install.
//
//   - higher version than current: allowed (if current >= min_supported_version)
//   - same version: ErrSameVersion
//   - lower version: only if the signed manifest lists `current` in
//     rollback_allowed_from (a deliberate, signed rollback for that exact version)
func (m *Manifest) Check(current, goos, goarch string) (*Artifact, error) {
	cur, err := ParseSemver(current)
	if err != nil {
		return nil, fmt.Errorf("current agent version: %w", err)
	}
	target, _ := ParseSemver(m.Version)
	switch c := target.Compare(cur); {
	case c == 0:
		return nil, fmt.Errorf("%w (%s)", ErrSameVersion, current)
	case c < 0:
		allowed := false
		for _, v := range m.RollbackAllowedFrom {
			if pv, _ := ParseSemver(v); pv.Compare(cur) == 0 && pv.Build == cur.Build {
				allowed = true
			}
		}
		if !allowed {
			return nil, fmt.Errorf("%w: %s -> %s", ErrDowngrade, current, m.Version)
		}
	default:
		if m.MinSupportedVersion != "" {
			if min, _ := ParseSemver(m.MinSupportedVersion); cur.Compare(min) < 0 {
				return nil, fmt.Errorf("%w (%s < %s)", ErrTooOld, current, m.MinSupportedVersion)
			}
		}
	}
	return m.ArtifactFor(goos, goarch)
}
