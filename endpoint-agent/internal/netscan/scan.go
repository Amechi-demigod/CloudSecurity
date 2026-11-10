package netscan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MaxBatchDevices is the largest number of devices in one uploaded batch.
const MaxBatchDevices = 500

// Uploader posts one JSON batch to the scan's upload path (the collector's
// authenticated client; internal/client.UploadNetworkBatch).
type Uploader interface {
	UploadNetworkBatch(ctx context.Context, path string, body []byte) error
}

// statusError is implemented by client.HTTPError.
type statusError interface{ StatusCode() int }

// Env holds everything the scan touches outside the process; every part is
// replaceable so tests never use the real network.
type Env struct {
	// Ping sends one ICMP echo; nil skips ICMP (non-Windows builds).
	Ping func(ctx context.Context, ip netip.Addr, timeout time.Duration) (bool, error)
	// ARP resolves an on-link address (SendARP); nil skips ARP.
	ARP func(ctx context.Context, ip netip.Addr) (mac string, ok bool)
	// OnLink reports whether ip is on a subnet this host is attached to.
	OnLink func(ip netip.Addr) bool
	// Dial opens TCP connections for the port check (default net.Dialer).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// LookupAddr is the reverse DNS lookup (default net.DefaultResolver).
	LookupAddr func(ctx context.Context, addr string) ([]string, error)

	SNMPPort    uint16        // default 161 (tests: a loopback fake agent)
	SNMPTimeout time.Duration // per request, default 1.5 s (one retry)
	SNMPBudget  time.Duration // per device, default 20 s
	DNSTimeout  time.Duration // default 1.5 s
	// Rate overrides the global packets-per-second cap (0: RateFor(concurrency); < 0: unlimited).
	Rate int
	// RetryDelays between upload attempts (default 2 s, 10 s, 30 s).
	RetryDelays []time.Duration
	// FlushEvery sends a partial batch this often so the console shows
	// progress (default 60 s; < 0 disables).
	FlushEvery time.Duration

	// Limiter is created by Run from the rate cap.
	Limiter *Limiter
}

// DefaultEnv is the production environment.
func DefaultEnv() *Env {
	return &Env{Ping: defaultPing(), ARP: defaultARP(), OnLink: localOnLink}
}

func (e *Env) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if e.Dial != nil {
		return e.Dial(ctx, network, addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// localOnLink reports whether ip lies in a prefix of a local interface.
func localOnLink(ip netip.Addr) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if p, ok := a.(*net.IPNet); ok {
			if pf, ok := netip.AddrFromSlice(p.IP.To4()); ok {
				ones, _ := p.Mask.Size()
				if netip.PrefixFrom(pf, ones).Contains(ip) {
					return true
				}
			}
		}
	}
	return false
}

// Device is one discovered (alive) host (contract: devices[]).
type Device struct {
	IP               string      `json:"ip"`
	MAC              string      `json:"mac,omitempty"`
	MACVendor        string      `json:"mac_vendor,omitempty"`
	Hostname         string      `json:"hostname,omitempty"`
	AliveVia         []string    `json:"alive_via"`
	SNMP             *SNMPInfo   `json:"snmp,omitempty"`
	DefaultCommunity *string     `json:"default_community"`
	Vendor           string      `json:"vendor,omitempty"`
	Model            string      `json:"model,omitempty"`
	Firmware         string      `json:"firmware,omitempty"`
	Serial           string      `json:"serial,omitempty"`
	DeviceType       string      `json:"device_type,omitempty"`
	Interfaces       []Interface `json:"interfaces,omitempty"`
	FDB              []FDBEntry  `json:"fdb,omitempty"`
	OpenPorts        []PortInfo  `json:"open_ports"`
}

// Summary rides on the final batch (contract).
type Summary struct {
	Addresses int      `json:"addresses"`
	Alive     int      `json:"alive"`
	SNMP      int      `json:"snmp"`
	DurationS int      `json:"duration_s"`
	Errors    []string `json:"errors"`
}

// Batch is one upload (contract).
type Batch struct {
	ScanID  string    `json:"scan_id"`
	Seq     int       `json:"seq"`
	Final   bool      `json:"final"`
	Devices []*Device `json:"devices"`
	Summary *Summary  `json:"summary,omitempty"`
}

// Result is the command result (contract).
type Result struct {
	ScanID    string   `json:"scan_id"`
	Addresses int      `json:"addresses"`
	Alive     int      `json:"alive"`
	SNMP      int      `json:"snmp"`
	DurationS int      `json:"duration_s"`
	Batches   int      `json:"batches"`
	Errors    []string `json:"errors"`
	// Failed: the server refused the upload (the scan was stopped).
	Failed bool `json:"-"`
}

var lastScan atomic.Pointer[Result]

// LastScan is the most recent scan's result (no secrets), or nil.
func LastScan() *Result { return lastScan.Load() }

type scanRun struct {
	e     *Env
	p     *Params
	ctx   context.Context
	creds []Credential

	scanned atomic.Int64
	errMu   sync.Mutex
	errs    []string
	errSeen map[string]bool
	pingErr atomic.Bool
}

const maxErrors = 50

func (r *scanRun) addErr(msg string) {
	msg = Redact(msg, r.p.Secrets()...)
	r.errMu.Lock()
	defer r.errMu.Unlock()
	if r.errSeen[msg] || len(r.errs) >= maxErrors {
		return
	}
	if r.errSeen == nil {
		r.errSeen = map[string]bool{}
	}
	r.errSeen[msg] = true
	r.errs = append(r.errs, msg)
}

// Redact removes secret values from a message.
func Redact(msg string, secrets ...string) string {
	for _, s := range secrets {
		if len(s) >= 3 {
			msg = strings.ReplaceAll(msg, s, "[redacted]")
		}
	}
	return msg
}

// Run performs one scan: a bounded worker pool probes every address, devices
// that are alive are uploaded in batches of at most 500, and a final batch
// carries the summary. It never panics on bad replies, stops cleanly when
// ctx ends (still sending a final batch with what it has) and returns the
// command result.
func (e *Env) Run(ctx context.Context, p *Params, uploadPath string, up Uploader) Result {
	start := time.Now()
	rate := e.Rate
	if rate == 0 {
		rate = RateFor(p.Concurrency)
	}
	env := *e // the limiter is per run
	env.Limiter = NewLimiter(rate)
	r := &scanRun{e: &env, p: p, ctx: ctx, creds: p.SNMP}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan netip.Addr, p.Concurrency)
	devs := make(chan *Device, p.Concurrency)
	go func() {
		defer close(jobs)
		p.Set.Each(func(a netip.Addr) bool {
			select {
			case jobs <- a:
				return true
			case <-runCtx.Done():
				return false
			}
		})
	}()
	var wg sync.WaitGroup
	for i := 0; i < p.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				if runCtx.Err() != nil {
					return
				}
				d := r.scanHost(runCtx, ip)
				r.scanned.Add(1)
				if d != nil {
					devs <- d // the collector loop below always drains
				}
			}
		}()
	}
	go func() { wg.Wait(); close(devs) }()

	res := Result{ScanID: p.ScanID}
	var pending []*Device
	seq := 0
	failed := false
	send := func(b Batch) error {
		b.Seq = seq
		if err := r.upload(ctx, uploadPath, up, b); err != nil {
			return err
		}
		seq++
		return nil
	}
	flush := func() {
		if len(pending) == 0 || failed {
			pending = nil
			return
		}
		if err := send(Batch{ScanID: p.ScanID, Devices: pending}); err != nil {
			failed = true
			r.addErr("upload to the server failed: " + err.Error())
			cancel()
		}
		pending = nil
	}
	var tick <-chan time.Time
	if e.FlushEvery >= 0 {
		d := e.FlushEvery
		if d == 0 {
			d = time.Minute
		}
		t := time.NewTicker(d)
		defer t.Stop()
		tick = t.C
	}
loop:
	for {
		select {
		case d, ok := <-devs:
			if !ok {
				break loop
			}
			res.Alive++
			if d.SNMP != nil {
				res.SNMP++
			}
			pending = append(pending, d)
			if len(pending) >= MaxBatchDevices {
				flush()
			}
		case <-tick:
			flush()
		}
	}
	if err := ctx.Err(); err != nil && !failed {
		n, total := int(r.scanned.Load()), p.Set.Count()
		if errors.Is(err, context.DeadlineExceeded) {
			r.addErr("scan stopped at its deadline: " + itoa(n) + " of " + itoa(total) + " addresses were scanned")
		} else {
			r.addErr("scan cancelled (the collector is stopping): " + itoa(n) + " of " + itoa(total) + " addresses were scanned")
		}
	}
	res.Addresses = int(r.scanned.Load())
	res.DurationS = int(time.Since(start).Round(time.Second) / time.Second)
	if !failed {
		r.errMu.Lock()
		errs := append([]string{}, r.errs...)
		r.errMu.Unlock()
		sum := &Summary{Addresses: res.Addresses, Alive: res.Alive, SNMP: res.SNMP, DurationS: res.DurationS, Errors: errs}
		// The final batch must go out even after cancellation / deadline.
		fctx, fcancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
		b := Batch{ScanID: p.ScanID, Final: true, Devices: pending, Summary: sum}
		b.Seq = seq
		if err := r.upload(fctx, uploadPath, up, b); err != nil {
			failed = true
			r.addErr("final upload to the server failed: " + err.Error())
		} else {
			seq++
		}
		fcancel()
	}
	res.Batches = seq
	res.Failed = failed
	r.errMu.Lock()
	res.Errors = append([]string{}, r.errs...)
	r.errMu.Unlock()
	if res.Errors == nil {
		res.Errors = []string{}
	}
	cp := res
	lastScan.Store(&cp)
	slog.Info("network scan finished", "scan_id", p.ScanID, "addresses", res.Addresses, "alive", res.Alive,
		"snmp", res.SNMP, "batches", res.Batches, "duration_s", res.DurationS, "errors", len(res.Errors))
	return res
}

func itoa(n int) string { return strconv.Itoa(n) }

// upload sends one batch with retries and back-off. The body is encoded once
// and re-sent unchanged, so a retry of the same seq is idempotent on the server.
func (r *scanRun) upload(ctx context.Context, path string, up Uploader, b Batch) error {
	if b.Devices == nil {
		b.Devices = []*Device{}
	}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(b); err != nil {
		return err
	}
	body := buf.Bytes()
	delays := r.e.RetryDelays
	if delays == nil {
		delays = []time.Duration{2 * time.Second, 10 * time.Second, 30 * time.Second}
	}
	for attempt := 0; ; attempt++ {
		err := up.UploadNetworkBatch(ctx, path, body)
		if err == nil {
			return nil
		}
		var se statusError
		if errors.As(err, &se) {
			if c := se.StatusCode(); c >= 400 && c < 500 && c != 408 && c != 429 {
				return err
			}
		}
		if attempt >= len(delays) || ctx.Err() != nil {
			return err
		}
		t := time.NewTimer(delays[attempt])
		select {
		case <-ctx.Done():
			t.Stop()
			return err
		case <-t.C:
		}
	}
}

// scanHost probes one address. It returns nil when nothing answered.
func (r *scanRun) scanHost(ctx context.Context, ip netip.Addr) *Device {
	e, p := r.e, r.p
	d := &Device{IP: ip.String(), AliveVia: []string{}, OpenPorts: []PortInfo{}}
	via := map[string]bool{}
	if e.Ping != nil && e.Limiter.Wait(ctx) == nil {
		ok, err := e.Ping(ctx, ip, p.Timeout)
		if err != nil && ctx.Err() == nil && r.pingErr.CompareAndSwap(false, true) {
			r.addErr("ICMP echo failed: " + err.Error())
		}
		via["icmp"] = ok
	}
	if e.ARP != nil && e.OnLink != nil && e.OnLink(ip) && e.Limiter.Wait(ctx) == nil {
		if mac, ok := e.ARP(ctx, ip); ok {
			via["arp"], d.MAC = true, mac
		}
	}
	if ctx.Err() != nil {
		return nil
	}
	if p.PortCheck {
		var mu sync.Mutex
		var wg sync.WaitGroup
		sem := make(chan struct{}, 8)
		for _, pt := range p.Ports {
			if pt.Proto != "tcp" {
				continue
			}
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer func() { <-sem; wg.Done() }()
				if e.Limiter.Wait(ctx) != nil {
					return
				}
				if info, ok := e.checkTCP(ctx, ip.String(), pt.Port, p.Timeout); ok {
					mu.Lock()
					d.OpenPorts = append(d.OpenPorts, info)
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if len(d.OpenPorts) > 0 {
			via["tcp"] = true
			sortPorts(d.OpenPorts)
		}
	}
	alive := via["icmp"] || via["arp"] || via["tcp"]
	if ctx.Err() != nil {
		return nil
	}
	if alive || len(r.creds) > 0 {
		if res := e.snmpProbe(ctx, ip.String(), r.creds, alive); res != nil {
			d.SNMP, d.DefaultCommunity = res.Info, res.DefaultCommunity
			d.Vendor, d.Model, d.Firmware, d.Serial, d.DeviceType = res.Vendor, res.Model, res.Firmware, res.Serial,
				res.DeviceType
			d.Interfaces, d.FDB = res.Interfaces, res.FDB
			via["snmp"] = true
			if p.PortCheck && hasUDP161(p.Ports) {
				d.OpenPorts = append(d.OpenPorts, PortInfo{Port: 161, Proto: "udp", Service: "snmp"})
				sortPorts(d.OpenPorts)
			}
		}
	}
	for _, k := range []string{"icmp", "arp", "tcp", "snmp"} {
		if via[k] {
			d.AliveVia = append(d.AliveVia, k)
		}
	}
	if len(d.AliveVia) == 0 {
		return nil
	}
	d.Hostname = r.reverse(ctx, ip.String())
	return d
}

func hasUDP161(ports []Port) bool {
	for _, p := range ports {
		if p.Port == 161 && p.Proto == "udp" {
			return true
		}
	}
	return false
}

func sortPorts(ps []PortInfo) {
	for i := 1; i < len(ps); i++ {
		for j := i; j > 0 && (ps[j].Proto < ps[j-1].Proto || ps[j].Proto == ps[j-1].Proto && ps[j].Port < ps[j-1].Port); j-- {
			ps[j], ps[j-1] = ps[j-1], ps[j]
		}
	}
}

// reverse is a short-timeout PTR lookup ("" when none).
func (r *scanRun) reverse(ctx context.Context, ip string) string {
	d := r.e.DNSTimeout
	if d == 0 {
		d = 1500 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	look := r.e.LookupAddr
	if look == nil {
		look = net.DefaultResolver.LookupAddr
	}
	names, err := look(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return cleanBanner([]byte(strings.TrimSuffix(names[0], ".")), 253)
}
