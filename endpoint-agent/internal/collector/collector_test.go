package collector

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/directory"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
)

const cid = "0123456789abcdef0123456789abcdef"

type fakeAPI struct {
	mu        sync.Mutex
	results   map[string]map[string]any
	posts     []string
	netPaths  []string
	netBodies []string
}

func (f *fakeAPI) PostJSON(_ context.Context, path string, in, _ any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.posts = append(f.posts, path)
	if strings.HasSuffix(path, "/result") {
		b, _ := json.Marshal(in)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		if f.results == nil {
			f.results = map[string]map[string]any{}
		}
		f.results[path] = m
	}
	return nil
}
func (f *fakeAPI) GetJSON(context.Context, string, any) error { return nil }
func (f *fakeAPI) UploadDirectoryBatch(context.Context, string, string, []byte) error {
	return errors.New("not used")
}
func (f *fakeAPI) UploadNetworkBatch(_ context.Context, path string, body []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.netPaths = append(f.netPaths, path)
	f.netBodies = append(f.netBodies, string(body))
	return nil
}

func cmd(t string, params map[string]any) model.Command {
	if params == nil {
		params = map[string]any{}
	}
	return model.Command{ID: strings.Repeat("a", 32), DeviceID: cid, Type: t, Params: params,
		Nonce: strings.Repeat("n", 32), ExpiresAt: time.Now().Add(time.Hour)}
}

func TestCommandSetIsExactlyDirectoryAndNetworkDiscoveryWork(t *testing.T) {
	want := []string{"check_for_update", "collector_diagnostics", "collector_health", "directory_sync", "network_scan",
		"network_subnets"}
	got := slices.Clone(AllowedCommands)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("collector command set %v, want exactly %v", got, want)
	}
	for _, bad := range []string{"run_script", "start_remote_session", "isolate_host", "restore_host", "lock_device",
		"wipe_device", "collect_logs", "restart_agent", "enable_lost_mode", "disable_lost_mode",
		"update_check_in_interval", "recheck_posture", ""} {
		if Allowed(bad) {
			t.Errorf("%q allowed", bad)
		}
		if err := Validate(cmd(bad, nil), cid, time.Now()); err == nil {
			t.Errorf("%q validated", bad)
		}
		f := &fakeAPI{}
		c := &Collector{API: f, ID: cid, Facts: func() Facts { return Facts{} }}
		c.handle(context.Background(), cmd(bad, nil))
		res := f.results["/api/collector/commands/"+strings.Repeat("a", 32)+"/result"]
		if res["status"] != "rejected" {
			t.Errorf("%q: %v", bad, res)
		}
		if o := c.Execute(context.Background(), cmd(bad, nil)); o.Status != "rejected" {
			t.Errorf("Execute(%q) = %s", bad, o.Status)
		}
	}
}

func TestValidateBindingExpiryParams(t *testing.T) {
	c := cmd(CmdHealth, nil)
	c.DeviceID = strings.Repeat("b", 32)
	if Validate(c, cid, time.Now()) == nil {
		t.Error("other collector accepted")
	}
	c = cmd(CmdHealth, nil)
	c.ExpiresAt = time.Now().Add(-time.Minute)
	if Validate(c, cid, time.Now()) == nil {
		t.Error("expired accepted")
	}
	if Validate(cmd(CmdHealth, map[string]any{"x": 1}), cid, time.Now()) == nil {
		t.Error("params on health accepted")
	}
	if Validate(cmd(CmdDiagnostics, map[string]any{"domain": "corp.example.com", "auth": "kerberos", "evil": 1}), cid,
		time.Now()) == nil {
		t.Error("unknown diagnostics parameter accepted")
	}
}

func TestDiagnosticsCommandReportsSteps(t *testing.T) {
	f := &fakeAPI{}
	c := &Collector{API: f, ID: cid, Facts: func() Facts { return Facts{RunAs: `CORP\svc-collector$`} }}
	var gotIdentity string
	c.Diagnostics = func(identity string) *directory.Diagnostics {
		gotIdentity = identity
		return &directory.Diagnostics{
			Locate: func(context.Context, *directory.Params) ([]string, bool) {
				return []string{"dc01.corp.example.com"}, true
			},
			Dial: func(context.Context, string, time.Duration) (net.Conn, error) {
				return nil, &net.OpError{Op: "dial", Err: errors.New("refused")}
			},
			Identity: identity,
		}
	}
	params := map[string]any{"domain": "corp.example.com", "security": "ldaps", "auth": "simple",
		"credential": map[string]any{"username": "svc", "password": "Sup3r-secret"}}
	c.handle(context.Background(), cmd(CmdDiagnostics, params))
	res := f.results["/api/collector/commands/"+strings.Repeat("a", 32)+"/result"]
	if res["status"] != "failed" || gotIdentity != `CORP\svc-collector$` {
		t.Fatalf("%v", res)
	}
	b, _ := json.Marshal(res)
	if strings.Contains(string(b), "Sup3r-secret") || !strings.Contains(string(b), "listed in DNS as a DC but not responding") {
		t.Error(string(b))
	}
}

func TestClassifyIdentity(t *testing.T) {
	for _, tc := range []struct{ acct, sid, dom, host, run, kind string }{
		{`NT AUTHORITY\SYSTEM`, "S-1-5-18", "CORP", "coll01.corp.example.com", `CORP\COLL01$`, "computer_account"},
		{`NT AUTHORITY\SYSTEM`, "S-1-5-18", "", "coll01", `NT AUTHORITY\SYSTEM`, "computer_account"},
		{`CORP\svc-collector$`, "S-1-5-21-1-2-3-1500", "CORP", "coll01", `CORP\svc-collector$`, "gmsa"},
		{`CORP\svc-ldap`, "S-1-5-21-1-2-3-1501", "CORP", "coll01", `CORP\svc-ldap`, "user"},
		{"", "", "", "", "", "unknown"},
	} {
		run, kind := ClassifyIdentity(tc.acct, tc.sid, tc.dom, tc.host)
		if run != tc.run || kind != tc.kind {
			t.Errorf("%+v: %s %s", tc, run, kind)
		}
	}
}

func TestHealthReturnsFacts(t *testing.T) {
	c := &Collector{ID: cid, Facts: func() Facts { return Facts{Hostname: "COLL01", IsDomainController: true} }}
	o := c.Execute(context.Background(), cmd(CmdHealth, nil))
	if o.Status != "succeeded" || !strings.Contains(o.Output, `"is_domain_controller":true`) {
		t.Error(o)
	}
}
