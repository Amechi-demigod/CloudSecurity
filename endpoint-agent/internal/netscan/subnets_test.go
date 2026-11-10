package netscan

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/directory"
)

type fakeDir struct {
	entries map[string][]directory.Entry // by base DN
	bases   []string
	closed  int
}

func (f *fakeDir) Search(_ context.Context, base, filter string, attrs []string, _ int, fn func(directory.Entry) error) error {
	f.bases = append(f.bases, base)
	es, ok := f.entries[base]
	if !ok {
		return errors.New("noSuchObject")
	}
	for _, e := range es {
		if err := fn(e); err != nil {
			return err
		}
	}
	return nil
}
func (f *fakeDir) Server() string { return "dc01.corp.example.com" }
func (f *fakeDir) Close() error   { f.closed++; return nil }

func ent(dn string, kv ...string) directory.Entry {
	e := directory.Entry{DN: dn, Attrs: map[string][][]byte{}}
	for i := 0; i+1 < len(kv); i += 2 {
		e.Attrs[strings.ToLower(kv[i])] = append(e.Attrs[strings.ToLower(kv[i])], []byte(kv[i+1]))
	}
	return e
}

type fakeDHCP struct {
	scopes map[string][]DHCPScope
	errs   map[string]error
	asked  []string
}

func (f *fakeDHCP) Scopes(_ context.Context, s string) ([]DHCPScope, error) {
	f.asked = append(f.asked, s)
	if e := f.errs[s]; e != nil {
		return nil, e
	}
	return f.scopes[s], nil
}

func TestSubnetsFromADSitesAndDHCP(t *testing.T) {
	cfg := "CN=Configuration,DC=corp,DC=example,DC=com"
	dir := &fakeDir{entries: map[string][]directory.Entry{
		"CN=Subnets,CN=Sites," + cfg: {
			ent("CN=10.20.0.0/16,CN=Subnets,CN=Sites,"+cfg, "cn", "10.20.0.0/16",
				"siteObject", "CN=HQ,CN=Sites,"+cfg, "description", "Head office"),
			ent("CN=10.10.0.0/24,...", "cn", "10.10.0.0/24", "siteObject", "CN=Branch-1,CN=Sites,"+cfg),
			ent("CN=2001:db8::/48,...", "cn", "2001:db8::/48", "siteObject", "CN=HQ,CN=Sites,"+cfg), // IPv6: skipped
			ent("CN=bad,...", "cn", "not-a-cidr"),
		},
		"CN=NetServices,CN=Services," + cfg: {
			ent("CN=DhcpRoot,...", "cn", "DhcpRoot", "dhcpServers", "i10.20.0.9$rignored.corp.example.com$"),
			ent("CN=10.20.0.5,...", "cn", "10.20.0.5"),
			ent("CN=dhcp02.corp.example.com,...", "cn", "dhcp02.corp.example.com"),
			ent("CN=weird,...", "cn", "bad name; rm -rf"),
		},
	}}
	dh := &fakeDHCP{
		scopes: map[string][]DHCPScope{"10.20.0.5": {{Server: "10.20.0.5", Scope: "10.20.1.0", Mask: "255.255.255.0",
			Name: "Floor 1", Start: "10.20.1.10", End: "10.20.1.200"}}},
		errs: map[string]error{"dhcp02.corp.example.com": errors.New("access denied: add the collector's account to the 'DHCP Users' group on dhcp02.corp.example.com")},
	}
	// a child domain: the first candidate (the child's own Configuration) does not exist
	env := &SubnetEnv{Domain: "emea.corp.example.com", DHCP: dh,
		Params:  &directory.Params{Domain: "emea.corp.example.com"},
		Connect: func(context.Context, *directory.Params) (directory.Searcher, error) { return dir, nil }}
	res, err := Subnets(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.ADSites) != 2 || res.ADSites[0].Subnet != "10.10.0.0/24" || res.ADSites[0].Site != "Branch-1" ||
		res.ADSites[1].Site != "HQ" || res.ADSites[1].Description != "Head office" {
		t.Errorf("%+v", res.ADSites)
	}
	if len(res.DHCPScopes) != 1 || res.DHCPScopes[0].Scope != "10.20.1.0" || res.DHCPScopes[0].Start != "10.20.1.10" {
		t.Errorf("%+v", res.DHCPScopes)
	}
	if len(dh.asked) != 2 || dh.asked[0] != "10.20.0.5" || dh.asked[1] != "dhcp02.corp.example.com" {
		t.Errorf("asked %v", dh.asked)
	}
	if len(res.Errors) != 1 || !strings.Contains(res.Errors[0], "DHCP Users") || !strings.Contains(res.Errors[0], "dhcp02") {
		t.Errorf("errors %v", res.Errors)
	}
	if dir.bases[0] != "CN=Subnets,CN=Sites,CN=Configuration,DC=emea,DC=corp,DC=example,DC=com" {
		t.Errorf("first base %q", dir.bases[0])
	}
	if dir.closed != 1 {
		t.Errorf("closed %d", dir.closed)
	}
	b, _ := json.Marshal(res)
	for _, k := range []string{`"ad_sites":[`, `"dhcp_scopes":[`, `"errors":[`, `"site":"HQ"`, `"subnet":"10.20.0.0/16"`,
		`"description":"Head office"`, `"mask":"255.255.255.0"`, `"start":"10.20.1.10"`, `"end":"10.20.1.200"`, `"name":"Floor 1"`,
		`"server":"10.20.0.5"`, `"scope":"10.20.1.0"`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("missing %s in %s", k, b)
		}
	}
}

func TestSubnetsPartialFailuresAreNotFatal(t *testing.T) {
	dir := &fakeDir{entries: map[string][]directory.Entry{}} // no Configuration anywhere
	env := &SubnetEnv{Domain: "corp.example.com", Params: &directory.Params{Domain: "corp.example.com"},
		Connect: func(context.Context, *directory.Params) (directory.Searcher, error) { return dir, nil }}
	res, err := Subnets(context.Background(), env)
	if err != nil || len(res.ADSites) != 0 || len(res.Errors) == 0 || res.DHCPScopes == nil {
		t.Fatalf("%v %+v", err, res)
	}
	// no DHCP client: reported, not fatal
	cfg := "CN=Configuration,DC=corp,DC=example,DC=com"
	dir = &fakeDir{entries: map[string][]directory.Entry{"CN=Subnets,CN=Sites," + cfg: nil,
		"CN=NetServices,CN=Services," + cfg: {ent("x", "cn", "10.0.0.1")}}}
	env.Connect = func(context.Context, *directory.Params) (directory.Searcher, error) { return dir, nil }
	res, err = Subnets(context.Background(), env)
	if err != nil || len(res.Errors) != 1 || !strings.Contains(res.Errors[0], "unsupported") {
		t.Errorf("%v %+v", err, res)
	}
	// cannot connect: the command fails
	env.Connect = func(context.Context, *directory.Params) (directory.Searcher, error) { return nil, errors.New("no DC") }
	if _, err := Subnets(context.Background(), env); err == nil {
		t.Error("connect failure ignored")
	}
}

func TestConfigRoots(t *testing.T) {
	got := configRoots("a.b.example.com")
	want := []string{"CN=Configuration,DC=a,DC=b,DC=example,DC=com", "CN=Configuration,DC=b,DC=example,DC=com",
		"CN=Configuration,DC=example,DC=com"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("%v", got)
	}
	if got := configRoots("corp.local"); len(got) != 1 {
		t.Errorf("%v", got)
	}
}

func TestDefaultSubnetEnvPlatform(t *testing.T) {
	env, err := DefaultSubnetEnv("corp.example.com")
	if subnetsSupported {
		if err != nil || env == nil {
			t.Fatal(err)
		}
	} else if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "unsupported on this platform") {
		t.Errorf("%v", err)
	}
}
