package update

import (
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed" // trusted_keys.txt
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// TrustedKey is an Ed25519 release-signing public key compiled into the agent.
type TrustedKey struct {
	ID  string
	Pub ed25519.PublicKey
}

// trustedKeysFile lists the production release-signing public keys, one per
// line: "<key id> <base64 32-byte public key> [comment]". It is committed to
// the repository (reviewable, never secret); scripts/agent-release-keygen
// prints the line to add. The private keys never touch this repository or the
// CNAPP server.
//
//go:embed trusted_keys.txt
var trustedKeysFile string

// ExtraTrustedKeys adds keys at build time (CI end-to-end tests with an
// ephemeral key), same line format, entries separated by ";":
//
//	-ldflags "-X github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/update.ExtraTrustedKeys=<id> <b64>"
//
// Release builds do not set it.
var ExtraTrustedKeys string

// KeyID derives the key identifier from the public key: "ed25519:" + the
// first 16 hex characters of SHA-256(public key). Deriving it means a manifest
// cannot claim a trusted key's ID for another key.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "ed25519:" + hex.EncodeToString(sum[:8])
}

// ParseKeys parses the trusted-key line format (blank lines and # comments ignored).
func ParseKeys(text string) ([]TrustedKey, error) {
	var keys []TrustedKey
	var entries []string
	for _, line := range strings.Split(text, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		entries = append(entries, strings.Split(line, ";")...)
	}
	for n, line := range entries {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			return nil, fmt.Errorf("trusted key entry %d: want \"<key id> <base64 public key>\"", n+1)
		}
		raw, err := base64.StdEncoding.DecodeString(f[1])
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("trusted key entry %d: not a base64 Ed25519 public key", n+1)
		}
		pub := ed25519.PublicKey(raw)
		if id := KeyID(pub); id != f[0] {
			return nil, fmt.Errorf("trusted key entry %d: key id %q does not match the key (%s)", n+1, f[0], id)
		}
		keys = append(keys, TrustedKey{ID: f[0], Pub: pub})
	}
	return keys, nil
}

// BuiltinKeys returns the keys compiled into this binary (committed file + ExtraTrustedKeys).
func BuiltinKeys() ([]TrustedKey, error) {
	keys, err := ParseKeys(trustedKeysFile)
	if err != nil {
		return nil, fmt.Errorf("embedded trusted_keys.txt: %w", err)
	}
	extra, err := ParseKeys(ExtraTrustedKeys)
	if err != nil {
		return nil, fmt.Errorf("ExtraTrustedKeys: %w", err)
	}
	seen := map[string]bool{}
	var out []TrustedKey
	for _, k := range append(keys, extra...) {
		if !seen[k.ID] {
			seen[k.ID] = true
			out = append(out, k)
		}
	}
	return out, nil
}
