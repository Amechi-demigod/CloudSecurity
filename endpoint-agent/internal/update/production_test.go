package update

import (
	"errors"
	"os"
	"testing"
	"time"
)

// TestProductionReleaseAcceptedByCIBuilds is a regression test for the
// question "why does a device running a CI-built MSI/PKG agent not take the
// published 1.0.0 release?". It uses the real, published signed manifest of
// agent-v1.0.0 (testdata, signed by the production release key) and the keys
// compiled into this package (trusted_keys.txt), and checks that agents with
// CI version strings (0.1.<run>+<sha>, as built by ci.yml for the MSI and the
// universal PKG) on every supported platform accept it.
func TestProductionReleaseAcceptedByCIBuilds(t *testing.T) {
	env, err := os.ReadFile("testdata/agent-v1.0.0.manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := ParseKeys(trustedKeysFile)
	if err != nil || len(keys) == 0 {
		t.Fatalf("committed trusted keys: %v (%d keys)", err, len(keys))
	}
	// A moment after the release was signed (manifest valid until 2027-04-18).
	now := time.Date(2026, 10, 20, 16, 0, 0, 0, time.UTC)
	m, err := Verify(env, keys, now)
	if err != nil {
		t.Fatalf("production manifest rejected: %v", err)
	}
	if m.Version != "1.0.0" || m.KeyID != "ed25519:38ab5e030fbeb143" {
		t.Fatalf("unexpected manifest %s signed by %s", m.Version, m.KeyID)
	}
	for _, cur := range []string{"0.1.132+1c918b1", "0.1.0+1c918b1", "0.1.0-dev", "0.9.9"} {
		// windows/amd64: the x64 MSI. darwin/arm64 and darwin/amd64: the universal
		// PKG runs the native slice, so runtime.GOARCH is the Mac's architecture.
		for _, p := range [][2]string{{"windows", "amd64"}, {"windows", "arm64"}, {"darwin", "arm64"}, {"darwin", "amd64"}} {
			a, err := m.Check(cur, p[0], p[1])
			if err != nil {
				t.Errorf("%s on %s/%s: %v", cur, p[0], p[1], err)
				continue
			}
			if a.OS != p[0] || a.Arch != p[1] {
				t.Errorf("%s on %s/%s: got artifact %s/%s", cur, p[0], p[1], a.OS, a.Arch)
			}
		}
	}
	// Build metadata is ignored for precedence: 1.0.0+abc is the same version.
	if _, err := m.Check("1.0.0+abc1234", "windows", "amd64"); !errors.Is(err, ErrSameVersion) {
		t.Errorf("1.0.0+abc1234 -> 1.0.0: %v, want ErrSameVersion", err)
	}
	// After expiry the manifest is refused (the server stops offering it too).
	if _, err := Verify(env, keys, m.ExpiresAt.Add(time.Second)); !errors.Is(err, ErrExpired) {
		t.Errorf("after expiry: %v, want ErrExpired", err)
	}
}
