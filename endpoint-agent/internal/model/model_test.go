package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNormalizeNoNullsAndLimits(t *testing.T) {
	r := Report{Device: DeviceInfo{Hostname: strings.Repeat("h", 300), OSVersion: "é" + strings.Repeat("x", 100)}}
	r.Normalize()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`"disks":[]`, `"network":[]`, `"logged_in_users":[]`, `"posture":{}`, `"errors":{}`, `"software":null`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in %s", want, s)
		}
	}
	if len(r.Device.Hostname) != 255 || len(r.Device.OSVersion) > 64 {
		t.Fatalf("not truncated: %d %d", len(r.Device.Hostname), len(r.Device.OSVersion))
	}
	if r.SchemaVersion != 1 {
		t.Fatal("schema version")
	}
}

func TestTruncUTF8(t *testing.T) {
	if got := Trunc("aé", 2); got != "a" {
		t.Fatalf("got %q", got)
	}
	if got := Trunc(" a\x00b ", 10); got != "ab" {
		t.Fatalf("got %q", got)
	}
}

func TestEmptySoftwareListStaysEmptyNotNull(t *testing.T) {
	r := Report{Software: []Software{{Name: ""}}}
	r.Normalize()
	b, _ := json.Marshal(r.Software)
	if string(b) != "[]" {
		t.Fatalf("got %s", b)
	}
}
