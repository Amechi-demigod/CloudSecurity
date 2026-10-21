package state

import (
	"testing"
)

func TestPolicyRoundTripAndPurge(t *testing.T) {
	p := Resolve(t.TempDir())
	pol, err := LoadPolicy(p)
	if err != nil || pol.AllowWipe {
		t.Fatalf("default policy %+v %v", pol, err)
	}
	if err := SavePolicy(p, Policy{AllowWipe: true, Source: "msi"}); err != nil {
		t.Fatal(err)
	}
	if pol, err := LoadPolicy(p); err != nil || !pol.AllowWipe || pol.Source != "msi" {
		t.Fatalf("%+v %v", pol, err)
	}
	if err := Remove(p); err != nil {
		t.Fatal(err)
	}
	if pol, _ := LoadPolicy(p); pol.AllowWipe {
		t.Fatal("purge kept the wipe opt-in")
	}
}

func TestParseBoolSetting(t *testing.T) {
	for in, want := range map[string]string{"": "nil", "1": "true", "TRUE": "true", "yes": "true", "0": "false", "off": "false"} {
		v, err := ParseBoolSetting(in)
		got := "nil"
		if v != nil {
			if *v {
				got = "true"
			} else {
				got = "false"
			}
		}
		if err != nil || got != want {
			t.Errorf("%q: %s %v", in, got, err)
		}
	}
	if _, err := ParseBoolSetting("maybe"); err == nil {
		t.Error("accepted maybe")
	}
}

func TestEnrollConfigAllowWipe(t *testing.T) {
	c, err := ParseEnrollConfig([]byte(`{"version":1,"server_url":"https://x.example","token":"cne_abcdefghijk","allow_wipe":true}`))
	if err != nil || !c.AllowWipe {
		t.Fatalf("%+v %v", c, err)
	}
}
