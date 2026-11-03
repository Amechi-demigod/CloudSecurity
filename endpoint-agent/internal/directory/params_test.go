package directory

import (
	"strings"
	"testing"
)

const (
	testRun    = "0123456789abcdef0123456789abcdef"
	testSource = "fedcba9876543210fedcba9876543210"
	testToken  = "tok_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_xyz"
	testPass   = "S3cret-Passw0rd!"
)

func validParams() map[string]any {
	return map[string]any{
		"source_id": testSource, "run_id": testRun, "domain": "Corp.Example.com",
		"servers": []any{"dc1.corp.example.com"}, "port": 636.0, "security": "ldaps",
		"base_dns": []any{"OU=Laptops,DC=corp,DC=example,DC=com"}, "scopes": []any{"computers", "users"},
		"page_size": 1000.0, "batch_size": 2000.0, "max_objects": 500000.0, "timeout_seconds": 3600.0,
		"auth": "simple", "ca_pem": "", "test": false,
		"upload_path": UploadPrefix + testRun + "/batches", "upload_token": testToken,
		"credential": map[string]any{"username": "svc-ldap@corp.example.com", "password": testPass},
	}
}

func TestParseParamsValid(t *testing.T) {
	p, err := ParseParams(validParams())
	if err != nil {
		t.Fatal(err)
	}
	if p.Domain != "corp.example.com" || p.Port != 636 || p.Username != "svc-ldap@corp.example.com" ||
		p.Password != testPass || p.PageSize != 1000 || len(p.Scopes) != 2 {
		t.Fatalf("%+v", p)
	}
	if strings.Contains(p.String(), testPass) || strings.Contains(p.String(), testToken) {
		t.Error("String() leaks a secret")
	}
	if DomainToDN("corp.example.com") != "DC=corp,DC=example,DC=com" {
		t.Error("DomainToDN")
	}
	m := validParams()
	delete(m, "base_dns")
	delete(m, "servers")
	p, _ = ParseParams(m)
	if b := p.SearchBases(); len(b) != 1 || b[0] != "DC=corp,DC=example,DC=com" {
		t.Errorf("%v", b)
	}
}

func TestParseParamsRejects(t *testing.T) {
	cases := map[string]func(m map[string]any){
		"unknown param":         func(m map[string]any) { m["filter"] = "(objectClass=*)" },
		"plain ldap":            func(m map[string]any) { m["security"] = "none" },
		"389 without starttls":  func(m map[string]any) { m["port"] = 389.0 },
		"bad host":              func(m map[string]any) { m["servers"] = []any{"dc1;rm -rf"} },
		"host flag":             func(m map[string]any) { m["servers"] = []any{"-oProxy"} },
		"too many hosts":        func(m map[string]any) { m["servers"] = make([]any, 11) },
		"bad domain":            func(m map[string]any) { m["domain"] = "corp example" },
		"bad scope":             func(m map[string]any) { m["scopes"] = []any{"groups"} },
		"dup scope":             func(m map[string]any) { m["scopes"] = []any{"users", "users"} },
		"no scope":              func(m map[string]any) { m["scopes"] = []any{} },
		"page too big":          func(m map[string]any) { m["page_size"] = 5000.0 },
		"fraction":              func(m map[string]any) { m["batch_size"] = 150.5 },
		"cap too big":           func(m map[string]any) { m["max_objects"] = 3e6 },
		"timeout":               func(m map[string]any) { m["timeout_seconds"] = 5.0 },
		"bad dn":                func(m map[string]any) { m["base_dns"] = []any{"corp"} },
		"simple without cred":   func(m map[string]any) { delete(m, "credential") },
		"empty password":        func(m map[string]any) { m["credential"] = map[string]any{"username": "u", "password": ""} },
		"extra cred field":      func(m map[string]any) { m["credential"].(map[string]any)["domain"] = "x" },
		"bad auth":              func(m map[string]any) { m["auth"] = "ntlm" },
		"bad upload path":       func(m map[string]any) { m["upload_path"] = "/api/agent/checkin" },
		"traversal upload path": func(m map[string]any) { m["upload_path"] = UploadPrefix + "../checkin" },
		"query upload path":     func(m map[string]any) { m["upload_path"] = UploadPrefix + "x?y=1" },
		"bad token":             func(m map[string]any) { m["upload_token"] = "short" },
		"bad ca":                func(m map[string]any) { m["ca_pem"] = "not a pem" },
		"bad id":                func(m map[string]any) { m["run_id"] = "../../x" },
		"test not bool":         func(m map[string]any) { m["test"] = "yes" },
	}
	for name, mut := range cases {
		m := validParams()
		mut(m)
		_, err := ParseParams(m)
		if err == nil {
			t.Errorf("%s accepted", name)
			continue
		}
		if strings.Contains(err.Error(), testPass) || strings.Contains(err.Error(), testToken) {
			t.Errorf("%s: error leaks a secret: %v", name, err)
		}
	}
}

func TestParseParamsStartTLSAndKerberos(t *testing.T) {
	m := validParams()
	m["security"], m["port"] = "starttls", 389.0
	if _, err := ParseParams(m); err != nil {
		t.Errorf("starttls on 389: %v", err)
	}
	m = validParams()
	m["auth"] = "kerberos"
	delete(m, "credential")
	_, err := ParseParams(m)
	if KerberosSupported() && err != nil {
		t.Errorf("kerberos on Windows: %v", err)
	}
	if !KerberosSupported() && (err == nil || !strings.Contains(err.Error(), "Windows")) {
		t.Errorf("kerberos accepted on a non-Windows collector: %v", err)
	}
	m = validParams()
	m["auth"] = "kerberos" // with a credential: never
	if _, err := ParseParams(m); err == nil {
		t.Error("kerberos with a credential accepted")
	}
}
