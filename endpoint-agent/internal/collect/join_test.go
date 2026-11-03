package collect

import (
	"testing"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
)

const dsconfigadBound = `Active Directory Forest          = example.com
Active Directory Domain          = corp.example.com
Computer Account                 = mac-ada$
Advanced Options - User Experience
  Create mobile account at login = Enabled
  Require confirmation           = Disabled
Advanced Options - Administrative
  Preferred Domain controller    = not set
`

func TestParseDsconfigad(t *testing.T) {
	j := ParseDsconfigad(dsconfigadBound)
	if j == nil || j.ADDomain != "corp.example.com" || j.ADForest != "example.com" ||
		j.DNSHostname != "mac-ada.corp.example.com" || j.Source != "dsconfigad" {
		t.Fatalf("%+v", j)
	}
	if ParseDsconfigad("") != nil || ParseDsconfigad("dsconfigad: this computer is not bound") != nil {
		t.Error("unbound Mac reported as joined")
	}
}

const realmOut = `example.org
  type: kerberos
  realm-name: EXAMPLE.ORG
  domain-name: example.org
  configured: no
corp.example.com
  type: kerberos
  realm-name: CORP.EXAMPLE.COM
  domain-name: corp.example.com
  configured: kerberos-member
  server-software: active-directory
  client-software: sssd
  required-package: sssd-tools
  login-formats: %U@corp.example.com
  login-policy: allow-realm-logins
`

func TestParseRealmList(t *testing.T) {
	j := ParseRealmList(realmOut, "web01")
	if j == nil || j.ADDomain != "corp.example.com" || j.DNSHostname != "web01.corp.example.com" || j.Source != "realm" {
		t.Fatalf("%+v", j)
	}
	if j := ParseRealmList(realmOut, "WEB01.corp.example.com"); j.DNSHostname != "web01.corp.example.com" {
		t.Errorf("fqdn host: %q", j.DNSHostname)
	}
	if ParseRealmList("example.org\n  configured: no\n", "h") != nil || ParseRealmList("", "h") != nil {
		t.Error("not-joined host reported as joined")
	}
}

func TestJoinNormalize(t *testing.T) {
	r := &model.Report{Device: model.DeviceInfo{Hostname: "h", DirectoryJoin: &model.DirectoryJoin{
		ADDomain: "CORP.Example.COM.", ADNetbios: "CORP", ADComputerSID: "s-1-5-21-1-2-3-1104",
		ADDomainSID: "not a sid", EntraDeviceID: "{0F1E2D3C-AAAA-BBBB-CCCC-123456789ABC}", EntraJoinType: "weird",
	}}}
	r.Normalize()
	j := r.Device.DirectoryJoin
	if j.ADDomain != "corp.example.com" || j.ADComputerSID != "S-1-5-21-1-2-3-1104" || j.ADDomainSID != "" ||
		j.EntraDeviceID != "0f1e2d3c-aaaa-bbbb-cccc-123456789abc" || j.EntraJoinType != "" {
		t.Fatalf("%+v", j)
	}
	r = &model.Report{Device: model.DeviceInfo{Hostname: "h", DirectoryJoin: &model.DirectoryJoin{DNSHostname: "h.lan"}}}
	r.Normalize()
	if r.Device.DirectoryJoin != nil {
		t.Error("a host name alone is not a directory join")
	}
}
