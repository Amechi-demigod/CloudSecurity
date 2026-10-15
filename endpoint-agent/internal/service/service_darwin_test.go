//go:build darwin

package service

import (
	"testing"

	pl "github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/plist"
)

func TestLaunchDaemonPlist(t *testing.T) {
	m, err := pl.DecodeDict([]byte(plist(serviceArgs(Options{Home: "/tmp/a & b"}))))
	if err != nil {
		t.Fatal(err)
	}
	args := m["ProgramArguments"].([]any)
	if pl.String(m, "Label") != LaunchdLabel || m["KeepAlive"] != true || m["RunAtLoad"] != true {
		t.Errorf("plist %v", m)
	}
	want := []string{BinaryPath, "run", "--home", "/tmp/a & b"}
	if len(args) != len(want) {
		t.Fatalf("args %v", args)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Errorf("arg %d: %v", i, args[i])
		}
	}
}
