package netscan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type httpErr int

func (e httpErr) Error() string   { return "http error" }
func (e httpErr) StatusCode() int { return int(e) }

// fakeServer records batches by seq (idempotent like the real server) and can
// fail the first attempt of every batch.
type fakeServer struct {
	mu       sync.Mutex
	bodies   map[int][]byte
	batches  map[int]Batch
	attempts int
	failOnce bool
	failWith error
	tried    map[int]bool
	paths    []string
	deliver  func()
}

func newFakeServer() *fakeServer {
	return &fakeServer{bodies: map[int][]byte{}, batches: map[int]Batch{}, tried: map[int]bool{}}
}

func (s *fakeServer) UploadNetworkBatch(_ context.Context, path string, body []byte) error {
	var b Batch
	if err := json.Unmarshal(body, &b); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts++
	s.paths = append(s.paths, path)
	if s.failWith != nil {
		return s.failWith
	}
	if s.failOnce && !s.tried[b.Seq] {
		s.tried[b.Seq] = true
		return httpErr(503)
	}
	if old, ok := s.bodies[b.Seq]; ok {
		if !bytes.Equal(old, body) {
			return errors.New("retry of the same seq with a different body")
		}
		return nil // idempotent
	}
	s.bodies[b.Seq], s.batches[b.Seq] = append([]byte(nil), body...), b
	return nil
}

func (s *fakeServer) all() (out []Batch) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := 0; i < len(s.batches); i++ {
		out = append(out, s.batches[i])
	}
	return
}

func params(t *testing.T, targets []string, mod func(m map[string]any)) *Params {
	t.Helper()
	m := map[string]any{"scan_id": "scan1", "targets": toAny(targets), "upload_url": "/api/collector/network/scan1/results",
		"concurrency": 20.0}
	if mod != nil {
		mod(m)
	}
	p, err := parseParams(m, true) // tests may use loopback / any block
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// testNet is TEST-NET-1/2/3 (RFC 5737, never routed): the scan tests only ever
// "probe" these through injected functions - nothing touches a network.
var testNet = []string{"192.0.2.0-192.0.2.255", "198.51.100.0-198.51.100.255", "203.0.113.0-203.0.113.255"}

func fastEnv() *Env {
	return &Env{Rate: -1, SNMPHost: func(ip string) (string, bool) { return ip, ip == "127.0.0.1" }, Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errors.New("test guard: no real connections in scan tests")
	}, RetryDelays: []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond},
		FlushEvery: -1, LookupAddr: func(ctx context.Context, a string) ([]string, error) { return []string{"h-" + a + "."}, nil },
		SNMPTimeout: 100 * time.Millisecond}
}

func TestBatchesSplitAt500FinalSummaryAndIdempotentRetries(t *testing.T) {
	e := fastEnv()
	e.Ping = func(context.Context, netip.Addr, time.Duration) (bool, error) { return true, nil }
	srv := newFakeServer()
	srv.failOnce = true          // every batch fails once with a 503 and is retried with the same body
	p := params(t, testNet, nil) // 768 addresses, all "alive"
	res := e.Run(context.Background(), p, "/api/collector/network/scan1/results", srv)
	bs := srv.all()
	if res.Failed || res.Alive != 768 || res.Addresses != 768 || len(bs) != 2 || res.Batches != 2 {
		t.Fatalf("%+v batches=%d", res, len(bs))
	}
	for i, b := range bs {
		if b.Seq != i || b.ScanID != "scan1" || len(b.Devices) > MaxBatchDevices {
			t.Errorf("batch %d: %+v", i, b)
		}
		if b.Final != (i == 1) {
			t.Errorf("batch %d final=%v", i, b.Final)
		}
	}
	if len(bs[0].Devices) != 500 || len(bs[1].Devices) != 268 {
		t.Errorf("sizes %d %d", len(bs[0].Devices), len(bs[1].Devices))
	}
	if bs[0].Summary != nil || bs[1].Summary == nil || bs[1].Summary.Addresses != 768 || bs[1].Summary.Alive != 768 ||
		bs[1].Summary.SNMP != 0 || bs[1].Summary.Errors == nil {
		t.Errorf("summary %+v", bs[1].Summary)
	}
	if srv.attempts != 4 { // each of the 2 batches was sent twice
		t.Errorf("attempts %d", srv.attempts)
	}
	seen := map[string]bool{}
	for _, b := range bs {
		for _, d := range b.Devices {
			if seen[d.IP] {
				t.Errorf("duplicate %s", d.IP)
			}
			seen[d.IP] = true
			if d.Hostname != "h-"+d.IP || len(d.AliveVia) != 1 || d.AliveVia[0] != "icmp" || d.OpenPorts == nil {
				t.Fatalf("%+v", d)
			}
		}
	}
	for _, path := range srv.paths {
		if path != "/api/collector/network/scan1/results" {
			t.Errorf("uploaded to %q", path)
		}
	}
	if LastScan() == nil || LastScan().ScanID != "scan1" {
		t.Error("last scan not recorded")
	}
}

func TestOnlyAliveDevicesAreReportedAndFinalBatchWithNoDevices(t *testing.T) {
	e := fastEnv()
	e.Ping = func(_ context.Context, ip netip.Addr, _ time.Duration) (bool, error) {
		return ip == netip.MustParseAddr("192.0.2.5"), nil
	}
	srv := newFakeServer()
	res := e.Run(context.Background(), params(t, []string{"192.0.2.0/24"}, nil), "/api/collector/x", srv)
	bs := srv.all()
	if res.Alive != 1 || res.Addresses != 254 || len(bs) != 1 || !bs[0].Final || len(bs[0].Devices) != 1 {
		t.Fatalf("%+v %+v", res, bs)
	}
	srv2 := newFakeServer()
	e.Ping = func(context.Context, netip.Addr, time.Duration) (bool, error) { return false, nil }
	e.Run(context.Background(), params(t, []string{"192.0.2.0/24"}, nil), "/api/collector/x", srv2)
	raw := string(srv2.bodies[0])
	if !strings.Contains(raw, `"devices":[]`) || !strings.Contains(raw, `"final":true`) {
		t.Errorf("empty scan: %s", raw)
	}
}

func TestPermanentUploadFailureStopsTheScan(t *testing.T) {
	e := fastEnv()
	var pings atomic.Int64
	e.Ping = func(context.Context, netip.Addr, time.Duration) (bool, error) { pings.Add(1); return true, nil }
	srv := newFakeServer()
	srv.failWith = httpErr(403)
	res := e.Run(context.Background(), params(t, testNet, nil), "/api/collector/x", srv)
	if !res.Failed || len(res.Errors) == 0 || pings.Load() >= 768 {
		t.Errorf("%+v pings=%d", res, pings.Load())
	}
	if srv.attempts > 3 {
		t.Errorf("retried a 403: %d attempts", srv.attempts)
	}
}

func TestWorkerPoolIsBounded(t *testing.T) {
	for _, conc := range []int{3, 20} {
		e := fastEnv()
		var cur, peak atomic.Int64
		e.Ping = func(context.Context, netip.Addr, time.Duration) (bool, error) {
			n := cur.Add(1)
			for {
				old := peak.Load()
				if n <= old || peak.CompareAndSwap(old, n) {
					break
				}
			}
			time.Sleep(2 * time.Millisecond)
			cur.Add(-1)
			return false, nil
		}
		p := params(t, []string{"192.0.2.0/24"}, func(m map[string]any) { m["concurrency"] = float64(conc) })
		e.Run(context.Background(), p, "/api/collector/x", newFakeServer())
		if got := int(peak.Load()); got > conc || got < min(conc, 2) {
			t.Errorf("concurrency %d: peak %d", conc, got)
		}
	}
}

func TestRateCap(t *testing.T) {
	if RateFor(20) != 200 || RateFor(64) != 500 {
		t.Error("RateFor")
	}
	l := NewLimiter(200)
	start := time.Now()
	for i := 0; i < 41; i++ {
		if err := l.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d < 190*time.Millisecond || d > time.Second {
		t.Errorf("41 packets at 200/s took %s", d)
	}
	// concurrent callers share the one cap
	l = NewLimiter(500)
	start = time.Now()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				_ = l.Wait(context.Background())
			}
		}()
	}
	wg.Wait()
	if d := time.Since(start); d < 380*time.Millisecond { // 200 packets / 500 per second = 400 ms
		t.Errorf("200 packets at 500/s took only %s", d)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	slow := NewLimiter(1)
	_ = slow.Wait(context.Background())
	if slow.Wait(ctx) == nil {
		t.Error("cancelled wait succeeded")
	}
	if err := (*Limiter)(nil).Wait(context.Background()); err != nil {
		t.Error(err)
	}
}

func TestScanUsesTheLimiterForEveryProbe(t *testing.T) {
	e := fastEnv()
	e.Rate = 400
	e.Ping = func(context.Context, netip.Addr, time.Duration) (bool, error) { return false, nil }
	p := params(t, []string{"192.0.2.0/25"}, nil) // 126 addresses -> 126 pings at 400/s >= ~310 ms
	start := time.Now()
	e.Run(context.Background(), p, "/api/collector/x", newFakeServer())
	if d := time.Since(start); d < 280*time.Millisecond {
		t.Errorf("scan ignored the rate cap: %s", d)
	}
}

func TestCancellationSendsFinalBatchWithWhatItHas(t *testing.T) {
	e := fastEnv()
	ctx, cancel := context.WithCancel(context.Background())
	var n atomic.Int64
	e.Ping = func(c context.Context, ip netip.Addr, _ time.Duration) (bool, error) {
		if n.Add(1) == 30 {
			cancel()
		}
		return true, nil
	}
	srv := newFakeServer()
	res := e.Run(ctx, params(t, testNet, func(m map[string]any) { m["concurrency"] = 5.0 }), "/api/collector/x", srv)
	bs := srv.all()
	if len(bs) == 0 || !bs[len(bs)-1].Final || res.Failed {
		t.Fatalf("%+v %d", res, len(bs))
	}
	sum := bs[len(bs)-1].Summary
	if res.Addresses >= 768 || res.Alive == 0 || len(sum.Errors) == 0 || !strings.Contains(sum.Errors[0], "cancelled") {
		t.Errorf("%+v %+v", res, sum)
	}
}

func TestDeadlineStopsTheScan(t *testing.T) {
	e := fastEnv()
	e.Ping = func(c context.Context, ip netip.Addr, _ time.Duration) (bool, error) {
		time.Sleep(10 * time.Millisecond)
		return false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	srv := newFakeServer()
	start := time.Now()
	res := e.Run(ctx, params(t, testNet, func(m map[string]any) { m["concurrency"] = 4.0 }), "/api/collector/x", srv)
	if time.Since(start) > 3*time.Second {
		t.Errorf("ran %s past a 150ms deadline", time.Since(start))
	}
	bs := srv.all()
	if len(bs) != 1 || !bs[0].Final || len(res.Errors) == 0 || !strings.Contains(res.Errors[0], "deadline") {
		t.Errorf("%+v %+v", res, bs)
	}
}

func TestScanFindsPortsAndSNMPOnLoopback(t *testing.T) {
	a := newFakeAgent(t, "good")
	a.populateSystem("Cisco IOS Switch", "1.3.6.1.4.1.9.1.1")
	a.populateInterfaces(2)
	a.finish()
	ssh := listen(t, func(c net.Conn) { _, _ = c.Write([]byte("SSH-2.0-Fake\r\n")) })
	e := fastEnv()
	e.SNMPPort = a.port()
	e.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, port, _ := net.SplitHostPort(addr)
		if port == "22" { // redirect the well-known port to the loopback test listener
			addr = net.JoinHostPort("127.0.0.1", itoa(ssh))
		} else {
			addr = "127.0.0.1:1" // closed
		}
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	p := params(t, []string{"127.0.0.1"}, func(m map[string]any) {
		m["port_check"] = true
		m["ports"] = []any{map[string]any{"port": 22.0, "proto": "tcp"}, map[string]any{"port": 23.0, "proto": "tcp"},
			map[string]any{"port": 161.0, "proto": "udp"}}
		m["snmp"] = []any{map[string]any{"id": "c1", "version": "v2c", "community": "good"}}
	})
	srv := newFakeServer()
	res := e.Run(context.Background(), p, "/api/collector/x", srv)
	bs := srv.all()
	if res.Alive != 1 || res.SNMP != 1 || len(bs) != 1 {
		t.Fatalf("%+v", res)
	}
	d := bs[0].Devices[0]
	if d.IP != "127.0.0.1" || strings.Join(d.AliveVia, ",") != "tcp,snmp" || d.SNMP == nil || d.SNMP.CredentialID != "c1" ||
		d.Vendor != "Cisco" || len(d.Interfaces) != 2 || d.DefaultCommunity != nil {
		t.Errorf("%+v", d)
	}
	if len(d.OpenPorts) != 2 || d.OpenPorts[0].Port != 22 || d.OpenPorts[0].Banner != "SSH-2.0-Fake" ||
		d.OpenPorts[1].Port != 161 || d.OpenPorts[1].Proto != "udp" {
		t.Errorf("%+v", d.OpenPorts)
	}
	raw := string(srv.bodies[0])
	if !strings.Contains(raw, `"default_community":null`) || strings.Contains(raw, "good") && strings.Contains(raw, `"community"`) {
		t.Errorf("%s", raw)
	}
}

func TestSecretsNeverReachResultsOrErrors(t *testing.T) {
	a := newFakeAgent(t, "Sup3rSecretCommunity")
	a.populateSystem("Switch", "1.3.6.1.4.1.9.1.1")
	a.finish()
	e := fastEnv()
	e.SNMPPort = a.port()
	e.Ping = func(context.Context, netip.Addr, time.Duration) (bool, error) {
		return true, errors.New("boom Sup3rSecretCommunity authpass-1 privpass-1")
	}
	p := params(t, []string{"127.0.0.1"}, func(m map[string]any) {
		m["snmp"] = []any{
			map[string]any{"id": "c1", "version": "v2c", "community": "Sup3rSecretCommunity"},
			map[string]any{"id": "c2", "version": "v3", "username": "u", "auth_proto": "SHA", "priv_proto": "AES128",
				"level": "authPriv", "auth_password": "authpass-1", "priv_password": "privpass-1"},
		}
	})
	srv := newFakeServer()
	res := e.Run(context.Background(), p, "/api/collector/x", srv)
	out, _ := json.Marshal(res)
	all := string(out)
	for _, b := range srv.bodies {
		all += string(b)
	}
	for _, s := range []string{"Sup3rSecretCommunity", "authpass-1", "privpass-1"} {
		if strings.Contains(all, s) {
			t.Errorf("%q in the results: %s", s, all)
		}
	}
	if !strings.Contains(all, "[redacted]") {
		t.Errorf("expected the echoed secret to be redacted: %s", all)
	}
	if json.Valid([]byte(all)) && false {
		t.Fatal()
	}
}
