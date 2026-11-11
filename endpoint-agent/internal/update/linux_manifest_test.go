package update

import "testing"

// A Linux release (agent 1.7.0) carries linux/amd64 and linux/arm64 update artifacts and the signed `packages`
// list of its .deb / .rpm installers. The agent must pick its own artifact and ignore the packages.
func TestLinuxArtifactsAndSignedPackages(t *testing.T) {
	k := newKey(t)
	m := baseManifest("1.7.0", artifactFor("linux", "amd64", []byte("a")), artifactFor("linux", "arm64", []byte("b")),
		artifactFor("windows", "amd64", []byte("c")))
	m["packages"] = []map[string]any{
		{"format": "deb", "arch": "amd64", "name": "cnapp-agent_1.7.0_amd64.deb", "sha256": "ab", "size": 1},
		{"format": "rpm", "arch": "arm64", "name": "cnapp-agent-1.7.0-1.aarch64.rpm", "sha256": "cd", "size": 2},
	}
	got, err := Verify(sign(t, m, k), []TrustedKey{k.TrustedKey}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	art, err := got.Check("1.6.0", "linux", "arm64")
	if err != nil || art.OS != "linux" || art.Arch != "arm64" {
		t.Fatalf("artifact %+v err %v", art, err)
	}
	if _, err := got.Check("1.6.0", "linux", "386"); err == nil {
		t.Error("no artifact for linux/386")
	}
}
