package netscan

import (
	"strings"
	"testing"
	"time"
)

func goodParams() map[string]any {
	return map[string]any{
		"scan_id": "0123456789abcdef0123456789abcdef", "targets": []any{"10.0.0.0/24"}, "exclude": []any{"10.0.0.1"},
		"port_check": true, "ports": []any{map[string]any{"port": 22.0, "proto": "tcp"}, map[string]any{"port": 161.0, "proto": "udp"}},
		"concurrency": 20.0, "timeout_ms": 1000.0,
		"snmp": []any{
			map[string]any{"id": "a", "version": "v3", "username": "mon", "auth_proto": "SHA256", "priv_proto": "AES128",
				"level": "authPriv", "auth_password": "authpass-1", "priv_password": "privpass-1"},
			map[string]any{"id": 7.0, "version": "v2c", "community": "s3cr3tcomm"},
		},
		"upload_url": "/api/collector/network/scans/0123/results",
	}
}

func TestParseParamsValid(t *testing.T) {
	p, err := ParseParams(goodParams())
	if err != nil {
		t.Fatal(err)
	}
	if p.ScanID == "" || p.Set.Count() != 253 || !p.PortCheck || len(p.Ports) != 2 || p.Concurrency != 20 ||
		p.Timeout != time.Second || len(p.SNMP) != 2 || p.SNMP[1].ID != 7.0 || p.SNMP[0].Level != "authPriv" {
		t.Errorf("%+v", p)
	}
	if got := p.Secrets(); len(got) != 3 {
		t.Errorf("secrets %v", got)
	}
}

func TestParseParamsDefaultsAndPortCheckOff(t *testing.T) {
	m := goodParams()
	delete(m, "ports")
	delete(m, "snmp")
	delete(m, "exclude")
	delete(m, "concurrency")
	delete(m, "timeout_ms")
	p, err := ParseParams(m)
	if err != nil || len(p.Ports) != len(DefaultPorts) || p.Concurrency != 20 || p.Timeout != time.Second {
		t.Fatalf("%v %+v", err, p)
	}
	m["port_check"] = false
	if p, _ = ParseParams(m); p.PortCheck || len(p.Ports) != 0 {
		t.Errorf("%+v", p)
	}
}

func TestParseParamsRejects(t *testing.T) {
	mod := func(f func(m map[string]any)) map[string]any { m := goodParams(); f(m); return m }
	for name, m := range map[string]map[string]any{
		"unknown key":      mod(func(m map[string]any) { m["evil"] = 1 }),
		"no scan id":       mod(func(m map[string]any) { delete(m, "scan_id") }),
		"bad scan id":      mod(func(m map[string]any) { m["scan_id"] = "../x" }),
		"loopback":         mod(func(m map[string]any) { m["targets"] = []any{"127.0.0.1"} }),
		"ipv6":             mod(func(m map[string]any) { m["targets"] = []any{"fe80::/64"} }),
		"huge":             mod(func(m map[string]any) { m["targets"] = []any{"10.0.0.0/8"} }),
		"targets type":     mod(func(m map[string]any) { m["targets"] = "10.0.0.0/24" }),
		"concurrency":      mod(func(m map[string]any) { m["concurrency"] = 500.0 }),
		"timeout low":      mod(func(m map[string]any) { m["timeout_ms"] = 5.0 }),
		"port 0":           mod(func(m map[string]any) { m["ports"] = []any{map[string]any{"port": 0.0, "proto": "tcp"}} }),
		"proto":            mod(func(m map[string]any) { m["ports"] = []any{map[string]any{"port": 22.0, "proto": "sctp"}} }),
		"port_check type":  mod(func(m map[string]any) { m["port_check"] = "yes" }),
		"no upload":        mod(func(m map[string]any) { delete(m, "upload_url") }),
		"upload elsewhere": mod(func(m map[string]any) { m["upload_url"] = "/api/agent/x" }),
		"upload traversal": mod(func(m map[string]any) { m["upload_url"] = "/api/collector/../agent" }),
		"upload query":     mod(func(m map[string]any) { m["upload_url"] = "/api/collector/x?y=1" }),
		"snmp version": mod(func(m map[string]any) {
			m["snmp"] = []any{map[string]any{"id": "a", "version": "v1", "community": "x"}}
		}),
		"v2c no community":  mod(func(m map[string]any) { m["snmp"] = []any{map[string]any{"id": "a", "version": "v2c"}} }),
		"snmp no id":        mod(func(m map[string]any) { m["snmp"] = []any{map[string]any{"version": "v2c", "community": "x"}} }),
		"v3 md5":            mod(func(m map[string]any) { m["snmp"].([]any)[0].(map[string]any)["auth_proto"] = "MD5" }),
		"v3 short password": mod(func(m map[string]any) { m["snmp"].([]any)[0].(map[string]any)["auth_password"] = "short" }),
		"v3 authPriv none":  mod(func(m map[string]any) { m["snmp"].([]any)[0].(map[string]any)["priv_proto"] = "none" }),
		"v3 level":          mod(func(m map[string]any) { m["snmp"].([]any)[0].(map[string]any)["level"] = "noAuthNoPriv" }),
		"too many creds": mod(func(m map[string]any) {
			var l []any
			for i := 0; i < 17; i++ {
				l = append(l, map[string]any{"id": "a", "version": "v2c", "community": "x"})
			}
			m["snmp"] = l
		}),
	} {
		if _, err := ParseParams(m); err == nil {
			t.Errorf("%s: accepted", name)
		} else {
			for _, s := range []string{"authpass-1", "privpass-1", "s3cr3tcomm"} {
				if strings.Contains(err.Error(), s) {
					t.Errorf("%s: error leaks a secret: %v", name, err)
				}
			}
		}
	}
}

func TestParseParamsAuthNoPrivIgnoresPrivFields(t *testing.T) {
	m := goodParams()
	c := m["snmp"].([]any)[0].(map[string]any)
	c["level"], c["priv_proto"] = "authNoPriv", "none"
	delete(c, "priv_password")
	p, err := ParseParams(m)
	if err != nil || p.SNMP[0].PrivProto != "NONE" {
		t.Fatalf("%v %+v", err, p)
	}
}

func TestUploadPath(t *testing.T) {
	if p, err := UploadPath("https://console.example.test/api/collector/network/x", "console.example.test"); err != nil ||
		p != "/api/collector/network/x" {
		t.Errorf("%q %v", p, err)
	}
	if _, err := UploadPath("https://other.example.test/api/collector/network/x", "console.example.test"); err == nil {
		t.Error("foreign host accepted")
	}
	if _, err := UploadPath("https://user:pw@console.example.test/api/collector/x", "console.example.test"); err == nil {
		t.Error("userinfo accepted")
	}
}
