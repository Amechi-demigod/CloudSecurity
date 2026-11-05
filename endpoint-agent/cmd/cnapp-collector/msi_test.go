package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/state"
)

const testToken = "cnct_abcdefghijklmnopqrstuvwxyz012345"

func presetValue(t *testing.T, doc map[string]any) string {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	// Same layout as the server's msipatch: prefix, base64, padded with dots.
	return "CNAPPPRESET:v1:" + base64.StdEncoding.EncodeToString(b) + strings.Repeat(".", 40)
}

func collectorPreset(t *testing.T, runAs string) string {
	doc := map[string]any{"version": 1, "kind": "collector", "server_url": "https://cnapp.example.com",
		"token": testToken, "name": "Collector 1", "service_display_name": "Example Collector"}
	if runAs != "" {
		doc["run_as"] = runAs
	}
	return presetValue(t, doc)
}

func TestPlanMSIInstall(t *testing.T) {
	old := state.TokenPrefix
	state.TokenPrefix = state.CollectorTokenPrefix
	defer func() { state.TokenPrefix = old }()
	placeholder := "CNAPPPRESET:UNSET:" + strings.Repeat(".", 100)

	t.Run("pre-configured, member server, LocalSystem", func(t *testing.T) {
		p, err := planMSIInstall(msiInput{Preset: collectorPreset(t, "")}, hostInstall{})
		if err != nil {
			t.Fatal(err)
		}
		if p.Enroll == nil || p.Enroll.Token != testToken || p.Enroll.ServerURL != "https://cnapp.example.com" {
			t.Fatalf("enrollment = %+v", p.Enroll)
		}
		if p.RunAs != "" || p.DisplayName != "Example Collector" {
			t.Fatalf("plan = %+v", p)
		}
	})
	t.Run("gMSA from the console download, overridden by the GMSA property", func(t *testing.T) {
		p, err := planMSIInstall(msiInput{Preset: collectorPreset(t, `CORP\svc-collector$`)}, hostInstall{})
		if err != nil || p.RunAs != `CORP\svc-collector$` {
			t.Fatalf("%+v %v", p, err)
		}
		p, err = planMSIInstall(msiInput{Preset: collectorPreset(t, `CORP\svc-collector$`), GMSA: `CORP\other$`}, hostInstall{})
		if err != nil || p.RunAs != `CORP\other$` {
			t.Fatalf("%+v %v", p, err)
		}
		p, err = planMSIInstall(msiInput{Preset: collectorPreset(t, `CORP\svc-collector$`), GMSA: "LocalSystem"}, hostInstall{})
		if err != nil || p.RunAs != "" {
			t.Fatalf("GMSA=LocalSystem must reset to LocalSystem: %+v %v", p, err)
		}
	})
	t.Run("bad GMSA format is rejected before anything happens", func(t *testing.T) {
		for _, g := range []string{"svc-collector", `CORP\svc-collector`, `CORP\svc collector$`, `CORP\svc;evil$`,
			`\svc$`, `CORP\` + strings.Repeat("a", 70) + "$"} {
			if _, err := planMSIInstall(msiInput{Preset: collectorPreset(t, ""), GMSA: g}, hostInstall{}); err == nil ||
				!strings.Contains(err.Error(), "GMSA must be") {
				t.Errorf("GMSA=%q: err = %v", g, err)
			}
		}
	})
	t.Run("domain controller: silent first install needs ALLOW_DOMAIN_CONTROLLER=1", func(t *testing.T) {
		dc := hostInstall{IsDC: true}
		if _, err := planMSIInstall(msiInput{Preset: collectorPreset(t, "")}, dc); err == nil ||
			!strings.Contains(err.Error(), "ALLOW_DOMAIN_CONTROLLER=1") {
			t.Fatalf("err = %v", err)
		}
		if _, err := planMSIInstall(msiInput{Preset: collectorPreset(t, ""), AllowDC: "0"}, dc); err == nil {
			t.Fatal("ALLOW_DOMAIN_CONTROLLER=0 must refuse")
		}
		if _, err := planMSIInstall(msiInput{Preset: collectorPreset(t, ""), AllowDC: "maybe"}, dc); err == nil {
			t.Fatal("an invalid ALLOW_DOMAIN_CONTROLLER must be rejected")
		}
		if _, err := planMSIInstall(msiInput{Preset: collectorPreset(t, ""), AllowDC: "1"}, dc); err != nil {
			t.Fatal(err)
		}
		// Upgrades / repairs of a collector already installed there do not ask again.
		if _, err := planMSIInstall(msiInput{}, hostInstall{IsDC: true, Enrolled: true}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("already enrolled: enrollment and previous identity kept", func(t *testing.T) {
		h := hostInstall{Enrolled: true, HasSaved: true,
			Saved: state.ServiceSettings{RunAs: `CORP\svc-collector$`, DisplayName: "Example Collector"}}
		p, err := planMSIInstall(msiInput{Preset: collectorPreset(t, "")}, h)
		if err != nil {
			t.Fatal(err)
		}
		if p.Enroll != nil || p.RunAs != `CORP\svc-collector$` || p.DisplayName != "Example Collector" {
			t.Fatalf("plan = %+v", p)
		}
		// A generic MSI (upgrade, GPO) with no properties at all.
		p, err = planMSIInstall(msiInput{Preset: placeholder}, h)
		if err != nil || p.Enroll != nil || p.RunAs != `CORP\svc-collector$` {
			t.Fatalf("%+v %v", p, err)
		}
	})
	t.Run("take-over of a zip-installed collector running as a gMSA", func(t *testing.T) {
		p, err := planMSIInstall(msiInput{Preset: collectorPreset(t, "")},
			hostInstall{Enrolled: true, ServiceAccount: `CORP\svc-collector$`})
		if err != nil || p.RunAs != `CORP\svc-collector$` || p.Enroll != nil {
			t.Fatalf("%+v %v", p, err)
		}
		p, err = planMSIInstall(msiInput{Preset: collectorPreset(t, "")},
			hostInstall{Enrolled: true, ServiceAccount: "LocalSystem"})
		if err != nil || p.RunAs != "" {
			t.Fatalf("%+v %v", p, err)
		}
		// A service that still exists wins over the recorded settings (e.g. switched with sc.exe).
		p, err = planMSIInstall(msiInput{}, hostInstall{Enrolled: true, ServiceAccount: "LocalSystem", HasSaved: true,
			Saved: state.ServiceSettings{RunAs: `CORP\svc-collector$`}})
		if err != nil || p.RunAs != "" {
			t.Fatalf("%+v %v", p, err)
		}
	})
	t.Run("generic MSI: properties, or nothing", func(t *testing.T) {
		p, err := planMSIInstall(msiInput{Preset: placeholder, Server: "https://cnapp.example.com", Token: testToken}, hostInstall{})
		if err != nil || p.Enroll == nil || p.Enroll.Token != testToken {
			t.Fatalf("%+v %v", p, err)
		}
		p, err = planMSIInstall(msiInput{Preset: placeholder}, hostInstall{})
		if err != nil || p.Enroll != nil {
			t.Fatalf("%+v %v", p, err)
		}
		if _, err := planMSIInstall(msiInput{Server: "https://cnapp.example.com", Token: "cne_agenttokennotcollector"}, hostInstall{}); err == nil {
			t.Fatal("an agent token must be refused")
		}
		if _, err := planMSIInstall(msiInput{Token: testToken}, hostInstall{}); err == nil {
			t.Fatal("a token without a server must be refused")
		}
		if _, err := planMSIInstall(msiInput{Server: "http://cnapp.example.com", Token: testToken}, hostInstall{}); err == nil {
			t.Fatal("http must be refused")
		}
	})
	t.Run("an agent preset is not a collector preset", func(t *testing.T) {
		v := presetValue(t, map[string]any{"version": 1, "server_url": "https://cnapp.example.com", "token": "cne_abcdefghijk"})
		if _, err := planMSIInstall(msiInput{Preset: v}, hostInstall{}); err == nil {
			t.Fatal("expected an error")
		}
		if _, err := planMSIInstall(msiInput{Preset: collectorPreset(t, "notagmsa")}, hostInstall{}); err == nil {
			t.Fatal("a preset with a malformed run_as must be refused")
		}
	})
}

func TestPurgeRemovesEverything(t *testing.T) {
	p := state.Resolve(t.TempDir())
	if err := state.SaveServiceSettings(p, state.ServiceSettings{RunAs: `CORP\svc$`}); err != nil {
		t.Fatal(err)
	}
	if err := state.Save(p, &state.State{ServerURL: "https://cnapp.example.com", DeviceID: "x", DeviceSecret: "cnc_x"}); err != nil {
		t.Fatal(err)
	}
	if err := purge(p); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := state.LoadServiceSettings(p); ok {
		t.Fatal("service.json left behind")
	}
	if _, err := state.Load(p); err == nil {
		t.Fatal("state.json left behind")
	}
}
