package directory

import (
	"encoding/binary"
	"strconv"
	"testing"
	"time"
)

func TestGUIDString(t *testing.T) {
	// [guid]'0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0'.ToByteArray()
	b := []byte{0x3c, 0x2d, 0x1e, 0x0f, 0x5a, 0x4b, 0x78, 0x69, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0}
	if g := GUIDString(b); g != "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0" {
		t.Fatal(g)
	}
	if GUIDString(b[:15]) != "" || GUIDString(nil) != "" {
		t.Error("short GUID accepted")
	}
}

// sidBytes encodes S-1-5-21-a-b-c-rid.
func sidBytes(subs ...uint32) []byte {
	b := []byte{1, byte(len(subs)), 0, 0, 0, 0, 0, 5}
	for _, s := range subs {
		b = binary.LittleEndian.AppendUint32(b, s)
	}
	return b
}

func TestSIDString(t *testing.T) {
	if s := SIDString(sidBytes(21, 1004336348, 1177238915, 682003330, 1104)); s != "S-1-5-21-1004336348-1177238915-682003330-1104" {
		t.Fatal(s)
	}
	if s := SIDString(sidBytes(32, 544)); s != "S-1-5-32-544" {
		t.Fatal(s)
	}
	for _, bad := range [][]byte{nil, {2, 1, 0, 0, 0, 0, 0, 5, 1, 0, 0, 0}, {1, 2, 0, 0, 0, 0, 0, 5, 1, 0, 0, 0}} {
		if SIDString(bad) != "" {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestFileTime(t *testing.T) {
	// 2026-10-01T08:00:00Z
	want := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	ft := want.Unix()*10_000_000 + fileTimeEpochDiff
	if got := FileTime(strconv.FormatInt(ft, 10)); got == nil || !got.Equal(want) {
		t.Fatalf("%v", got)
	}
	for _, never := range []string{"0", "9223372036854775807", "", "abc", "-5"} {
		if FileTime(never) != nil {
			t.Errorf("%q should be null", never)
		}
	}
}

func TestGeneralizedTime(t *testing.T) {
	want := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, s := range []string{"20240102030405.0Z", "20240102030405Z"} {
		if got := GeneralizedTime(s); got == nil || !got.Equal(want) {
			t.Errorf("%s: %v", s, got)
		}
	}
	if GeneralizedTime("yesterday") != nil {
		t.Error("garbage parsed")
	}
}

func TestUACAndClean(t *testing.T) {
	if Int("4098") != 4098 || !Disabled(4098) || Disabled(4096) || Int("x") != 0 {
		t.Error("uac")
	}
	if c := clean("a\x00b\nc\xff", 100); c != "abc?" {
		t.Errorf("%q", c)
	}
	if c := clean("ééé", 3); c != "é" {
		t.Errorf("%q", c)
	}
}

func TestComputerFromEntry(t *testing.T) {
	g := []byte{0x3c, 0x2d, 0x1e, 0x0f, 0x5a, 0x4b, 0x78, 0x69, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0}
	e := Entry{DN: "CN=PC1,OU=Laptops,DC=corp,DC=example,DC=com", Attrs: map[string][][]byte{
		"objectguid": {g}, "objectsid": {sidBytes(21, 1, 2, 3, 1104)}, "cn": {[]byte("PC1")},
		"dnshostname": {[]byte("PC1.Corp.Example.com")}, "useraccountcontrol": {[]byte("4096")},
		"lastlogontimestamp": {[]byte("0")}, "whencreated": {[]byte("20240102030405.0Z")},
	}}
	c, ok := ComputerFromEntry(e)
	if !ok || c.ObjectGUID != "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0" || c.ObjectSID != "S-1-5-21-1-2-3-1104" ||
		c.DNSHostname != "pc1.corp.example.com" || c.DistinguishedName != e.DN || c.UserAccountControl != 4096 ||
		c.LastLogonTimestamp != nil || c.WhenCreated == nil {
		t.Fatalf("%+v", c)
	}
	if _, ok := ComputerFromEntry(Entry{Attrs: map[string][][]byte{"cn": {[]byte("x")}}}); ok {
		t.Error("entry without objectGUID accepted")
	}
}
