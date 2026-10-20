package update

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

type testKey struct {
	TrustedKey
	priv ed25519.PrivateKey
}

func newKey(t *testing.T) testKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{TrustedKey{ID: KeyID(pub), Pub: pub}, priv}
}

func artifactFor(goos, goarch string, data []byte) Artifact {
	sum := sha256.Sum256(data)
	return Artifact{OS: goos, Arch: goarch, Name: "cnapp-agent-" + goos + "-" + goarch, SHA256: hex.EncodeToString(sum[:]),
		Size: int64(len(data))}
}

func baseManifest(version string, arts ...Artifact) map[string]any {
	return map[string]any{
		"schema": 1, "product": Product, "version": version,
		"released_at": testNow.Add(-time.Hour).Format(time.RFC3339), "expires_at": testNow.Add(90 * 24 * time.Hour).Format(time.RFC3339),
		"min_supported_version": "0.1.0", "artifacts": arts,
	}
}

func sign(t *testing.T, m map[string]any, keys ...testKey) []byte {
	t.Helper()
	payload, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	env := Envelope{Payload: base64.StdEncoding.EncodeToString(payload)}
	for _, k := range keys {
		sig := ed25519.Sign(k.priv, append([]byte(SignatureContext), payload...))
		env.Signatures = append(env.Signatures, Signature{KeyID: k.ID, Sig: base64.StdEncoding.EncodeToString(sig)})
	}
	b, _ := json.Marshal(env)
	return b
}

func TestVerifyValid(t *testing.T) {
	k := newKey(t)
	env := sign(t, baseManifest("1.2.0", artifactFor("windows", "amd64", []byte("bin"))), k)
	m, err := Verify(env, []TrustedKey{k.TrustedKey}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != "1.2.0" || m.KeyID != k.ID {
		t.Fatalf("unexpected manifest %+v", m)
	}
	if _, err := m.Check("1.1.0", "windows", "amd64"); err != nil {
		t.Fatalf("upgrade refused: %v", err)
	}
}

func TestVerifyRejections(t *testing.T) {
	k, other := newKey(t), newKey(t)
	trusted := []TrustedKey{k.TrustedKey}
	art := artifactFor("darwin", "arm64", []byte("bin"))
	good := baseManifest("1.2.0", art)
	with := func(key string, v any) map[string]any {
		m := map[string]any{}
		for kk, vv := range good {
			m[kk] = vv
		}
		m[key] = v
		return m
	}
	tampered := func() []byte {
		env := sign(t, good, k)
		var e Envelope
		_ = json.Unmarshal(env, &e)
		p, _ := base64.StdEncoding.DecodeString(e.Payload)
		p = []byte(strings.Replace(string(p), "1.2.0", "9.9.9", 1))
		e.Payload = base64.StdEncoding.EncodeToString(p)
		b, _ := json.Marshal(e)
		return b
	}
	wrongKeyIDClaim := func() []byte {
		// Signed by an untrusted key but claiming the trusted key's id.
		payload, _ := json.Marshal(good)
		sig := ed25519.Sign(other.priv, append([]byte(SignatureContext), payload...))
		b, _ := json.Marshal(Envelope{Payload: base64.StdEncoding.EncodeToString(payload),
			Signatures: []Signature{{KeyID: k.ID, Sig: base64.StdEncoding.EncodeToString(sig)}}})
		return b
	}
	noContext := func() []byte {
		// Signature over the bare payload (no domain-separation prefix).
		payload, _ := json.Marshal(good)
		sig := ed25519.Sign(k.priv, payload)
		b, _ := json.Marshal(Envelope{Payload: base64.StdEncoding.EncodeToString(payload),
			Signatures: []Signature{{KeyID: k.ID, Sig: base64.StdEncoding.EncodeToString(sig)}}})
		return b
	}
	cases := []struct {
		name string
		env  []byte
		keys []TrustedKey
		want error
	}{
		{"untrusted key", sign(t, good, other), trusted, ErrNoTrustedKey},
		{"unsigned", sign(t, good), trusted, ErrNoTrustedKey},
		{"no trusted keys compiled in", sign(t, good, k), nil, ErrNoTrustedKey},
		{"tampered payload", tampered(), trusted, ErrBadSignature},
		{"trusted key id, other key's signature", wrongKeyIDClaim(), trusted, ErrBadSignature},
		{"signature without context prefix", noContext(), trusted, ErrBadSignature},
		{"expired", sign(t, with("expires_at", testNow.Add(-time.Minute).Format(time.RFC3339)), k), trusted, ErrExpired},
		{"released in the future", sign(t, with("released_at", testNow.Add(72*time.Hour).Format(time.RFC3339)), k), trusted, ErrNotYetValid},
		{"wrong product", sign(t, with("product", "evil"), k), trusted, ErrMalformed},
		{"schema 2", sign(t, with("schema", 2), k), trusted, ErrMalformed},
		{"bad version", sign(t, with("version", "1.2"), k), trusted, ErrMalformed},
		{"no artifacts", sign(t, with("artifacts", []Artifact{}), k), trusted, ErrMalformed},
		{"bad sha", sign(t, with("artifacts", []Artifact{{OS: "darwin", Arch: "arm64", SHA256: "abc", Size: 3}}), k), trusted, ErrMalformed},
		{"huge artifact", sign(t, with("artifacts", []Artifact{{OS: "darwin", Arch: "arm64", SHA256: art.SHA256, Size: MaxArtifactBytes + 1}}), k), trusted, ErrMalformed},
		{"duplicate platform", sign(t, with("artifacts", []Artifact{art, art}), k), trusted, ErrMalformed},
		{"not json", []byte("{"), trusted, ErrMalformed},
		{"oversized", []byte(strings.Repeat(" ", MaxManifestBytes+1)), trusted, ErrMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Verify(c.env, c.keys, testNow)
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

func TestKeyRotationAnySignatureFromTrustedKey(t *testing.T) {
	oldK, newK := newKey(t), newKey(t)
	env := sign(t, baseManifest("1.2.0", artifactFor("windows", "amd64", []byte("x"))), oldK, newK)
	for _, keys := range [][]TrustedKey{{oldK.TrustedKey}, {newK.TrustedKey}, {newK.TrustedKey, oldK.TrustedKey}} {
		if _, err := Verify(env, keys, testNow); err != nil {
			t.Fatalf("dual-signed manifest rejected with keys %v: %v", keys[0].ID, err)
		}
	}
}

func TestCheckVersionPolicy(t *testing.T) {
	k := newKey(t)
	mk := func(version string, extra map[string]any) *Manifest {
		m := baseManifest(version, artifactFor("windows", "amd64", []byte("x")))
		for kk, v := range extra {
			m[kk] = v
		}
		got, err := Verify(sign(t, m, k), []TrustedKey{k.TrustedKey}, testNow)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	cases := []struct {
		name, current, goos, goarch string
		m                           *Manifest
		want                        error
	}{
		{"upgrade", "1.0.0", "windows", "amd64", mk("1.1.0", nil), nil},
		{"upgrade from pre-release dev build", "0.1.0-dev", "windows", "amd64", mk("0.1.0", map[string]any{"min_supported_version": "0.0.0"}), nil},
		{"dev build below minimum supported", "0.1.0-dev", "windows", "amd64", mk("0.1.0", nil), ErrTooOld},
		{"downgrade", "1.2.0", "windows", "amd64", mk("1.1.0", nil), ErrDowngrade},
		{"downgrade ignores build metadata", "1.1.0+abc", "windows", "amd64", mk("1.1.0+def", nil), ErrSameVersion},
		{"same version", "1.1.0", "windows", "amd64", mk("1.1.0", nil), ErrSameVersion},
		{"signed rollback for this version", "1.2.0", "windows", "amd64", mk("1.1.0", map[string]any{"rollback_allowed_from": []string{"1.2.0"}}), nil},
		{"signed rollback for another version", "1.3.0", "windows", "amd64", mk("1.1.0", map[string]any{"rollback_allowed_from": []string{"1.2.0"}}), ErrDowngrade},
		{"below minimum supported", "0.0.9", "windows", "amd64", mk("1.1.0", map[string]any{"min_supported_version": "1.0.0"}), ErrTooOld},
		{"unknown platform", "1.0.0", "linux", "amd64", mk("1.1.0", nil), ErrNoArtifact},
		{"unknown arch", "1.0.0", "windows", "arm64", mk("1.1.0", nil), ErrNoArtifact},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := c.m.Check(c.current, c.goos, c.goarch)
			if c.want == nil && err != nil || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

func TestParseKeys(t *testing.T) {
	k := newKey(t)
	line := k.ID + " " + base64.StdEncoding.EncodeToString(k.Pub) + " # release key 2026"
	keys, err := ParseKeys("# comment\n\n" + line + "\n")
	if err != nil || len(keys) != 1 || keys[0].ID != k.ID {
		t.Fatalf("ParseKeys = %v, %v", keys, err)
	}
	other := newKey(t)
	if _, err := ParseKeys(other.ID + " " + base64.StdEncoding.EncodeToString(k.Pub)); err == nil {
		t.Fatal("a key id that does not match the key must be rejected")
	}
	if _, err := ParseKeys(k.ID + " not-base64"); err == nil {
		t.Fatal("garbage key accepted")
	}
	if keys, err := ParseKeys(k.ID + " " + base64.StdEncoding.EncodeToString(k.Pub) + ";" + other.ID + " " + base64.StdEncoding.EncodeToString(other.Pub)); err != nil || len(keys) != 2 {
		t.Fatalf("';'-separated ldflags form: %v %v", keys, err)
	}
	if _, err := BuiltinKeys(); err != nil {
		t.Fatalf("committed trusted_keys.txt does not parse: %v", err)
	}
}

func TestSemver(t *testing.T) {
	ordered := []string{"0.1.0-dev", "0.1.0", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
		"1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.10.0", "2.0.0"}
	for i := 0; i+1 < len(ordered); i++ {
		if c, err := CompareVersions(ordered[i], ordered[i+1]); err != nil || c != -1 {
			t.Fatalf("%s < %s: got %d %v", ordered[i], ordered[i+1], c, err)
		}
	}
	if c, _ := CompareVersions("1.2.3+a", "1.2.3+b"); c != 0 {
		t.Fatal("build metadata must be ignored")
	}
	for _, bad := range []string{"", "1", "1.2", "1.2.3.4", "01.2.3", "1.2.3-", "1.2.3+", "1.2.3-01", "a.b.c", "1.2.3-a_b"} {
		if _, err := ParseSemver(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}
