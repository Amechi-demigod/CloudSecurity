package plist

import (
	"strings"
	"testing"
	"time"
)

const sample = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleName</key>
	<string>Safari &amp; Co</string>
	<key>Count</key>
	<integer>3</integer>
	<key>Ratio</key>
	<real>1.5</real>
	<key>Enabled</key>
	<true/>
	<key>Off</key>
	<false/>
	<key>When</key>
	<date>2026-10-01T08:30:00Z</date>
	<key>Blob</key>
	<data>
	aGVs
	bG8=
	</data>
	<key>List</key>
	<array>
		<dict><key>Display Name</key><string>macOS 15.1</string></dict>
		<string>x</string>
	</array>
</dict>
</plist>`

func TestDecode(t *testing.T) {
	m, err := DecodeDict([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if String(m, "CFBundleName") != "Safari & Co" {
		t.Errorf("name %v", m["CFBundleName"])
	}
	if n, ok := Int(m, "Count"); !ok || n != 3 {
		t.Errorf("count %v", m["Count"])
	}
	if m["Ratio"].(float64) != 1.5 || m["Enabled"] != true || m["Off"] != false {
		t.Errorf("scalars %v", m)
	}
	if ts, ok := Time(m, "When"); !ok || !ts.Equal(time.Date(2026, 10, 1, 8, 30, 0, 0, time.UTC)) {
		t.Errorf("date %v", m["When"])
	}
	if string(m["Blob"].([]byte)) != "hello" {
		t.Errorf("data %v", m["Blob"])
	}
	list := m["List"].([]any)
	if len(list) != 2 || String(list[0].(map[string]any), "Display Name") != "macOS 15.1" {
		t.Errorf("list %v", list)
	}
}

func TestBinaryRejected(t *testing.T) {
	if _, err := Decode([]byte("bplist00\x00\x01")); err != ErrBinary {
		t.Fatalf("got %v", err)
	}
}

func TestTooDeep(t *testing.T) {
	s := "<plist>" + strings.Repeat("<array>", 100) + strings.Repeat("</array>", 100) + "</plist>"
	if _, err := Decode([]byte(s)); err == nil {
		t.Fatal("expected depth error")
	}
}

func TestGarbage(t *testing.T) {
	if _, err := DecodeDict([]byte("not xml")); err == nil {
		t.Fatal("expected error")
	}
	if _, err := DecodeDict([]byte("<plist><array></array></plist>")); err == nil {
		t.Fatal("expected not-a-dict error")
	}
}
