package collector

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/directory"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/netscan"
)

func scanParams() map[string]any {
	return map[string]any{
		"scan_id": "scan1", "targets": []any{"192.0.2.0/28"}, // TEST-NET-1: never routed; every probe below is injected
		"port_check": false, "concurrency": 20.0, "timeout_ms": 500.0,
		"snmp":       []any{map[string]any{"id": "c1", "version": "v2c", "community": "Sup3rSecretCommunity"}},
		"upload_url": "/api/collector/network/scans/scan1/results",
	}
}

// offlineEnv answers pings in-process; SNMP and TCP never leave the process.
func offlineEnv(alive func(netip.Addr) bool) func() *netscan.Env {
	return func() *netscan.Env {
		return &netscan.Env{Rate: -1, FlushEvery: -1,
			Ping:       func(_ context.Context, ip netip.Addr, _ time.Duration) (bool, error) { return alive(ip), nil },
			Dial:       func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("offline") },
			SNMPHost:   func(string) (string, bool) { return "", false },
			LookupAddr: func(context.Context, string) ([]string, error) { return nil, errors.New("offline") }}
	}
}

func resultOf(f *fakeAPI) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.results["/api/collector/commands/"+strings.Repeat("a", 32)+"/result"]
}

func TestNetworkScanCommandRunsInBackgroundAndReportsResult(t *testing.T) {
	f := &fakeAPI{}
	c := &Collector{API: f, ID: cid, Facts: func() Facts { return Facts{} }}
	c.NetEnv = offlineEnv(func(ip netip.Addr) bool { return ip.As4()[3]%2 == 0 })
	c.handle(context.Background(), cmd(CmdNetworkScan, scanParams()))
	c.WaitDirectorySync(10 * time.Second)
	res := resultOf(f)
	if res == nil || res["status"] != "succeeded" {
		t.Fatalf("%v", res)
	}
	data, _ := res["result_data"].(map[string]any)
	for _, k := range []string{"scan_id", "addresses", "alive", "snmp", "duration_s", "batches", "errors"} {
		if _, ok := data[k]; !ok {
			t.Errorf("result_data lacks %q: %v", k, data)
		}
	}
	if data["scan_id"] != "scan1" || data["addresses"] != 14.0 || data["alive"] != 7.0 || data["batches"] != 1.0 {
		t.Errorf("%v", data)
	}
	if len(f.netPaths) != 1 || f.netPaths[0] != "/api/collector/network/scans/scan1/results" {
		t.Errorf("uploads %v", f.netPaths)
	}
	var b netscan.Batch
	if err := json.Unmarshal([]byte(f.netBodies[0]), &b); err != nil || !b.Final || len(b.Devices) != 7 || b.Summary.Alive != 7 {
		t.Errorf("%v %+v", err, b)
	}
	// secrets: nothing the collector reported or uploaded contains the community
	rb, _ := json.Marshal(res)
	if strings.Contains(string(rb)+f.netBodies[0], "Sup3rSecretCommunity") {
		t.Error("secret in the reported data")
	}
}

func TestNetworkScanRejectionsAndSingleSlot(t *testing.T) {
	f := &fakeAPI{}
	c := &Collector{API: f, ID: cid, Facts: func() Facts { return Facts{} }}
	bad := scanParams()
	bad["targets"] = []any{"127.0.0.1"}
	if err := Validate(cmd(CmdNetworkScan, bad), cid, time.Now()); err == nil || !strings.Contains(err.Error(), "never scanned") {
		t.Errorf("loopback target validated: %v", err)
	}
	if err := Validate(cmd(CmdNetworkScan, scanParams()), cid, time.Now()); err != nil {
		t.Errorf("good scan rejected: %v", err)
	}
	c.handle(context.Background(), cmd(CmdNetworkScan, map[string]any{"targets": []any{"10.0.0.0/8"}}))
	if res := resultOf(f); res == nil || res["status"] != "rejected" {
		t.Errorf("%v", res)
	}
	if Validate(cmd(CmdNetworkSubnets, map[string]any{"x": 1}), cid, time.Now()) == nil {
		t.Error("params on network_subnets accepted")
	}
	// a second scan while one runs: the slot is single
	release := make(chan struct{})
	c.NetEnv = func() *netscan.Env {
		e := offlineEnv(func(netip.Addr) bool { return false })()
		e.Ping = func(ctx context.Context, _ netip.Addr, _ time.Duration) (bool, error) {
			select {
			case <-release:
			case <-ctx.Done():
			}
			return false, nil
		}
		return e
	}
	p, path, o := c.prepareScan(cmd(CmdNetworkScan, scanParams()))
	if p == nil {
		t.Fatalf("%v", o)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); c.runScan(context.Background(), cmd(CmdNetworkScan, scanParams()), p, path) }()
	time.Sleep(50 * time.Millisecond)
	if _, _, o := c.prepareScan(cmd(CmdNetworkScan, scanParams())); o.Status != "failed" || !strings.Contains(o.Output, "already running") {
		t.Errorf("%+v", o)
	}
	close(release)
	wg.Wait()
	if _, _, o := c.prepareScan(cmd(CmdNetworkScan, scanParams())); o.Status != "" {
		t.Errorf("slot not released: %+v", o)
	}
}

func TestNetworkScanStopsAtTheCommandDeadline(t *testing.T) {
	f := &fakeAPI{}
	c := &Collector{API: f, ID: cid, Facts: func() Facts { return Facts{} }}
	c.NetEnv = func() *netscan.Env {
		e := offlineEnv(func(netip.Addr) bool { return true })()
		e.Ping = func(ctx context.Context, _ netip.Addr, _ time.Duration) (bool, error) {
			time.Sleep(30 * time.Millisecond)
			return true, nil
		}
		return e
	}
	m := scanParams()
	m["targets"] = []any{"192.0.2.0-192.0.2.255"}
	m["concurrency"] = 2.0
	cm := cmd(CmdNetworkScan, m)
	cm.ExpiresAt = time.Now().Add(200 * time.Millisecond)
	start := time.Now()
	o := c.Execute(context.Background(), cm)
	if time.Since(start) > 3*time.Second || o.Status != "succeeded" {
		t.Fatalf("%s %+v", time.Since(start), o)
	}
	data := o.ResultData.(netscan.Result)
	if data.Addresses >= 256 || len(data.Errors) == 0 || !strings.Contains(data.Errors[0], "deadline") {
		t.Errorf("%+v", data)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.netBodies) == 0 || !strings.Contains(f.netBodies[len(f.netBodies)-1], `"final":true`) {
		t.Error("no final batch after the deadline")
	}
}

func TestNetworkSubnetsCommand(t *testing.T) {
	c := &Collector{ID: cid, Facts: func() Facts { return Facts{Domain: "corp.example.com"} }}
	c.SubnetEnv = func(domain string) (*netscan.SubnetEnv, error) {
		if domain != "corp.example.com" {
			t.Errorf("domain %q", domain)
		}
		return &netscan.SubnetEnv{Domain: domain, Params: &directory.Params{Domain: domain},
			Connect: func(context.Context, *directory.Params) (directory.Searcher, error) {
				return nil, errors.New("no domain controller")
			}}, nil
	}
	o := c.Execute(context.Background(), cmd(CmdNetworkSubnets, nil))
	if o.Status != "failed" || !strings.Contains(o.Output, "no domain controller") {
		t.Errorf("%+v", o)
	}
	c.SubnetEnv = func(string) (*netscan.SubnetEnv, error) { return nil, netscan.ErrUnsupported }
	if o := c.Execute(context.Background(), cmd(CmdNetworkSubnets, nil)); o.Status != "failed" ||
		!strings.Contains(o.Output, "unsupported on this platform") {
		t.Errorf("%+v", o)
	}
}

func TestDiagnosticsHaveANetworkSectionWithoutSecrets(t *testing.T) {
	f := &fakeAPI{}
	c := &Collector{API: f, ID: cid, Facts: func() Facts { return Facts{} }}
	c.NetEnv = offlineEnv(func(netip.Addr) bool { return true })
	c.Execute(context.Background(), cmd(CmdNetworkScan, scanParams())) // records the last scan summary
	c.Diagnostics = func(identity string) *directory.Diagnostics {
		return &directory.Diagnostics{
			Locate: func(context.Context, *directory.Params) ([]string, bool) {
				return []string{"dc01.corp.example.com"}, true
			},
			Dial: func(context.Context, string, time.Duration) (net.Conn, error) {
				return nil, &net.OpError{Op: "dial", Err: errors.New("refused")}
			}}
	}
	c.handle(context.Background(), cmd(CmdDiagnostics, map[string]any{"domain": "corp.example.com", "security": "ldaps",
		"auth": "simple", "credential": map[string]any{"username": "svc", "password": "Sup3r-secret"}}))
	res := resultOf(f)
	data, _ := res["result_data"].(map[string]any)
	nw, _ := data["network"].(map[string]any)
	if nw == nil || nw["last_scan"] == nil || nw["icmp_available"] == nil || nw["arp_available"] == nil {
		t.Fatalf("%v", data)
	}
	if data["steps"] == nil {
		t.Error("the directory steps disappeared")
	}
	b, _ := json.Marshal(res)
	for _, s := range []string{"Sup3rSecretCommunity", "Sup3r-secret"} {
		if strings.Contains(string(b), s) {
			t.Errorf("%q in diagnostics", s)
		}
	}
}
