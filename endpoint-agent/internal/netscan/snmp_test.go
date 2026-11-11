package netscan

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

func testEnv(a *fakeAgent) *Env {
	return &Env{SNMPPort: a.port(), SNMPTimeout: 150 * time.Millisecond, SNMPBudget: 20 * time.Second}
}

func v2(id, comm string) Credential { return Credential{ID: id, Version: "v2c", Community: comm} }

func TestSNMPCredentialOrderStopsAtFirstSuccess(t *testing.T) {
	a := newFakeAgent(t, "good")
	a.populateSystem("Cisco IOS Software, C3750E Switch", "1.3.6.1.4.1.9.1.516")
	a.populateInterfaces(3)
	a.finish()
	creds := []Credential{v2("c1", "wrong1"), v2("c2", "good"), v2("c3", "never-tried")}
	res := testEnv(a).snmpProbe(context.Background(), "127.0.0.1", creds, true)
	if res == nil || res.Info == nil {
		t.Fatal("no SNMP result")
	}
	if res.Info.CredentialID != "c2" || res.Info.Version != "v2c" || res.Info.SysName != "sw-core-1" ||
		res.Info.SysLocation != "Rack 4" || res.Info.SysContact != "noc@example.test" || res.Info.UptimeS != 3600 ||
		res.Info.SysObjectID != "1.3.6.1.4.1.9.1.516" {
		t.Errorf("%+v", res.Info)
	}
	if a.countCommunity("wrong1") == 0 {
		t.Error("first credential not tried")
	}
	if n := a.countCommunity("never-tried"); n != 0 {
		t.Errorf("credential after the first success was tried %d times", n)
	}
	// order of first appearance
	var seen []string
	for _, r := range a.requests() {
		if len(seen) == 0 || seen[len(seen)-1] != r.Community {
			seen = append(seen, r.Community)
		}
	}
	if seen[0] != "wrong1" || seen[1] != "good" {
		t.Errorf("order %v", seen)
	}
	if res.Vendor != "Cisco" || res.Model != "WS-C3750X-48P" || res.Firmware != "15.2(7)E3" || res.Serial != "FOC1234X0AB" ||
		res.DeviceType != "switch" {
		t.Errorf("hints %+v", res)
	}
	if len(res.Interfaces) != 3 || res.Interfaces[0].Name != "Gi1/0/1" || res.Interfaces[0].SpeedMbps != 1000 ||
		res.Interfaces[0].MAC != "00:1b:2c:3d:4e:01" || !res.Interfaces[1].OperUp || res.Interfaces[0].OperUp {
		t.Errorf("%+v", res.Interfaces)
	}
	if a.setSeen {
		t.Error("an SNMP SET was sent")
	}
}

func TestDefaultCommunityProbeLimits(t *testing.T) {
	// A supplied v2c credential answers; "public" and "private" are each tried exactly once.
	a := newFakeAgent(t, "good")
	a.populateSystem("Linux host", "1.3.6.1.4.1.8072.3.2.10")
	a.finish()
	res := testEnv(a).snmpProbe(context.Background(), "127.0.0.1", []Credential{v2("c1", "good")}, true)
	if res == nil || res.Info == nil || res.DefaultCommunity != nil {
		t.Fatalf("%+v", res)
	}
	if a.countCommunity("public") != 1 || a.countCommunity("private") != 1 {
		t.Errorf("public=%d private=%d, want 1 each", a.countCommunity("public"), a.countCommunity("private"))
	}
	for _, r := range a.requests() {
		if r.Community != "good" && r.Community != "public" && r.Community != "private" {
			t.Errorf("unexpected community %q", r.Community)
		}
	}

	// Nothing supplied; the device answers the default "public" (once each, no retry).
	b := newFakeAgent(t, "public")
	b.populateSystem("Printer", "1.3.6.1.4.1.11.2.3.9.1")
	b.finish()
	res = testEnv(b).snmpProbe(context.Background(), "127.0.0.1", nil, true)
	if res == nil || res.DefaultCommunity == nil || *res.DefaultCommunity != "public" || res.Info != nil {
		t.Fatalf("%+v", res)
	}
	if b.countCommunity("public") != 1 || b.countCommunity("private") != 1 || len(b.requests()) != 2 {
		t.Errorf("requests: %v", b.requests())
	}
	// Both answer: the more serious "private" is reported.
	c := newFakeAgent(t, "public", "private")
	c.populateSystem("x", "1.3.6.1.4.1.9.1.1")
	c.finish()
	res = testEnv(c).snmpProbe(context.Background(), "127.0.0.1", nil, true)
	if res == nil || res.DefaultCommunity == nil || *res.DefaultCommunity != "private" {
		t.Fatalf("%+v", res)
	}
	// A supplied community equal to "public" is not re-sent.
	d := newFakeAgent(t, "public")
	d.populateSystem("x", "1.3.6.1.4.1.9.1.1")
	d.finish()
	res = testEnv(d).snmpProbe(context.Background(), "127.0.0.1", []Credential{v2("p", "public")}, true)
	if res == nil || res.DefaultCommunity == nil || *res.DefaultCommunity != "public" {
		t.Fatalf("%+v", res)
	}
	n := 0
	for _, r := range d.requests() {
		if r.Community == "public" && len(r.OIDs) == 1 && r.OIDs[0] == oidSysDescr && r.Type == gosnmp.GetRequest {
			n++
		}
	}
	if n != 0 {
		t.Errorf("single-OID default probe sent for an already-known community (%d)", n)
	}
	// A host that is not alive and has no credentials is not probed at all.
	e := newFakeAgent(t, "public")
	e.finish()
	if res := testEnv(e).snmpProbe(context.Background(), "127.0.0.1", nil, false); res != nil || len(e.requests()) != 0 {
		t.Errorf("probed a silent host without credentials: %v %v", res, e.requests())
	}
}

func TestSilentHostWithV3CredentialIsNotProbedWithDefaults(t *testing.T) {
	// A v3 success must not trigger the default-community probe: simulated by checking the decision
	// logic through a v2c-only agent that a v3 credential cannot reach.
	a := newFakeAgent(t) // answers nothing
	a.finish()
	res := testEnv(a).snmpProbe(context.Background(), "127.0.0.1", []Credential{{ID: "v3", Version: "v3",
		Username: "u", AuthProto: "SHA", AuthPassword: "authpass123", Level: "authNoPriv"}}, false)
	if res != nil {
		t.Errorf("%+v", res)
	}
	for _, r := range a.requests() {
		if r.Community == "public" || r.Community == "private" {
			t.Errorf("default community sent for a silent, not-alive host")
		}
	}
}

func TestInterfaceAndFDBCaps(t *testing.T) {
	a := newFakeAgent(t, "good")
	a.populateSystem("Switch", "1.3.6.1.4.1.9.1.1")
	a.populateInterfaces(600)
	a.populateFDB(5000)
	a.finish()
	res := testEnv(a).snmpProbe(context.Background(), "127.0.0.1", []Credential{v2("c", "good")}, true)
	if res == nil || res.Info == nil {
		t.Fatal("no result")
	}
	if len(res.Interfaces) != maxInterfaces {
		t.Errorf("%d interfaces, want cap %d", len(res.Interfaces), maxInterfaces)
	}
	if len(res.FDB) != maxFDB {
		t.Errorf("%d FDB entries, want cap %d", len(res.FDB), maxFDB)
	}
	if res.FDB[0].VLAN != 10 || !strings.HasPrefix(res.FDB[0].MAC, "00:11:22:") || res.FDB[0].PortName != "Gi1/0/1" {
		t.Errorf("%+v", res.FDB[0])
	}
	// GETBULK with small max-repetitions, never a SET.
	bulk := 0
	for _, r := range a.requests() {
		if r.Type == gosnmp.GetBulkRequest {
			bulk++
		}
	}
	if bulk == 0 || a.setSeen {
		t.Errorf("bulk=%d set=%v", bulk, a.setSeen)
	}
}

func TestSNMPBudgetStopsAWalk(t *testing.T) {
	a := newFakeAgent(t, "good")
	a.populateSystem("Switch", "1.3.6.1.4.1.9.1.1")
	a.populateInterfaces(500)
	a.finish()
	e := testEnv(a)
	e.SNMPBudget = 30 * time.Millisecond
	start := time.Now()
	e.snmpProbe(context.Background(), "127.0.0.1", []Credential{v2("c", "good")}, true)
	if time.Since(start) > 3*time.Second {
		t.Errorf("a 30ms budget took %s", time.Since(start))
	}
}

func TestV3ConfigMarshalling(t *testing.T) {
	e := &Env{}
	g := e.buildSNMP(context.Background(), "192.0.2.1", Credential{ID: "x", Version: "v3", Username: "monitor",
		AuthProto: "SHA256", PrivProto: "AES256", Level: "authPriv", AuthPassword: "authpass-1", PrivPassword: "privpass-1"}, 1)
	sp := g.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if g.Version != gosnmp.Version3 || g.MsgFlags != gosnmp.AuthPriv || g.SecurityModel != gosnmp.UserSecurityModel ||
		sp.AuthenticationProtocol != gosnmp.SHA256 || sp.PrivacyProtocol != gosnmp.AES256 || sp.UserName != "monitor" ||
		sp.AuthenticationPassphrase != "authpass-1" || sp.PrivacyPassphrase != "privpass-1" || g.Port != 161 ||
		g.Retries != 1 || g.MaxRepetitions != bulkReps {
		t.Errorf("%+v %+v", g, sp)
	}
	g = e.buildSNMP(context.Background(), "192.0.2.1", Credential{Version: "v3", Username: "u", AuthProto: "SHA",
		Level: "authNoPriv", AuthPassword: "authpass-1"}, 0)
	sp = g.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if g.MsgFlags != gosnmp.AuthNoPriv || sp.AuthenticationProtocol != gosnmp.SHA || sp.PrivacyProtocol != gosnmp.NoPriv {
		t.Errorf("%+v", sp)
	}
	g = e.buildSNMP(context.Background(), "192.0.2.1", v2("c", "comm"), 1)
	if g.Version != gosnmp.Version2c || g.Community != "comm" || g.Timeout != 1500*time.Millisecond {
		t.Errorf("%+v", g)
	}
}

func TestCredentialNeverFormatsSecrets(t *testing.T) {
	c := Credential{ID: "c1", Version: "v3", Username: "u", AuthPassword: "S3cretAuth!", PrivPassword: "S3cretPriv!",
		Community: "Sup3rComm"}
	p := &Params{ScanID: "s1", Set: &AddrSet{spans: []span{{1, 2}}}, SNMP: []Credential{c}}
	out := fmt.Sprintf("%v|%+v|%#v|%s|%v|%+v", c, c, c, c, []Credential{c}, p)
	var sb strings.Builder
	l := slog.New(slog.NewTextHandler(&sb, nil))
	l.Info("x", "cred", c, "p", p, "creds", p.SNMP)
	out += sb.String()
	for _, s := range []string{"S3cretAuth!", "S3cretPriv!", "Sup3rComm"} {
		if strings.Contains(out, s) {
			t.Errorf("%q leaked: %s", s, out)
		}
	}
	if Redact("auth S3cretAuth! failed", p.Secrets()...) != "auth [redacted] failed" {
		t.Error("Redact")
	}
}

func TestSophosFirewallReadsSFOSMIB(t *testing.T) {
	// Values from a real XGS2100 (LibreNMS test capture): sysDescr is plain Linux, no ENTITY-MIB.
	a := newFakeAgent(t, "good")
	a.str("1.3.6.1.2.1.1.1.0", "Linux localhost 6.6.116 #1 SMP Wed Jun  3 08:00:50 CDT 2026 x86_64")
	a.set("1.3.6.1.2.1.1.2.0", gosnmp.ObjectIdentifier, ".1.3.6.1.4.1.2604.5")
	a.str("1.3.6.1.2.1.1.5.0", "hq-fw")
	a.str("1.3.6.1.4.1.2604.5.1.1.1.0", "hq-fw")
	a.str("1.3.6.1.4.1.2604.5.1.1.2.0", "XGS2100_RL01_SFOS")
	a.str("1.3.6.1.4.1.2604.5.1.1.3.0", "22.0.2 MR-2-Build546")
	a.str("1.3.6.1.4.1.2604.5.1.1.4.0", "X21987654321012")
	a.finish()
	res := testEnv(a).snmpProbe(context.Background(), "127.0.0.1", []Credential{v2("c1", "good")}, true)
	if res == nil || res.Info == nil {
		t.Fatal("no SNMP result")
	}
	if res.Vendor != "Sophos" || res.DeviceType != "firewall" || res.Model != "XGS2100_RL01_SFOS" ||
		res.Firmware != "22.0.2 MR-2-Build546" || res.Serial != "X21987654321012" {
		t.Errorf("hints %+v", res)
	}
}

func TestSFOSMIBNotQueriedForOtherVendors(t *testing.T) {
	a := newFakeAgent(t, "good")
	a.populateSystem("Cisco IOS Software, C3750E Switch", "1.3.6.1.4.1.9.1.516")
	a.finish()
	if res := testEnv(a).snmpProbe(context.Background(), "127.0.0.1", []Credential{v2("c1", "good")}, true); res == nil {
		t.Fatal("no SNMP result")
	}
	for _, r := range a.requests() {
		for _, o := range r.OIDs {
			if strings.Contains(o, "2604.5") {
				t.Fatalf("Sophos OID %s requested from a Cisco device", o)
			}
		}
	}
}
