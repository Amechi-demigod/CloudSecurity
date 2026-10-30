package remote

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/remote/wire"
)

// --- fakes -------------------------------------------------------------------

type sent struct {
	binary bool
	data   []byte
}

type fakeConn struct {
	in     chan serverMsg
	mu     sync.Mutex
	out    []sent
	closed bool
	once   sync.Once
}

func newConn() *fakeConn { return &fakeConn{in: make(chan serverMsg, 32)} }

func (c *fakeConn) Read(ctx context.Context) (bool, []byte, error) {
	select {
	case m, ok := <-c.in:
		if !ok {
			return false, nil, errors.New("closed")
		}
		return m.binary, m.data, nil
	case <-ctx.Done():
		return false, nil, ctx.Err()
	}
}

func (c *fakeConn) Write(_ context.Context, binary bool, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("closed")
	}
	c.out = append(c.out, sent{binary, append([]byte(nil), data...)})
	return nil
}

func (c *fakeConn) Close(int, string) error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}

func (c *fakeConn) server(m wire.Msg) { c.in <- serverMsg{data: wire.Encode(m)} }

func (c *fakeConn) hangUp() { c.once.Do(func() { close(c.in) }) }

func (c *fakeConn) msgs() []wire.Msg {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []wire.Msg
	for _, s := range c.out {
		if !s.binary {
			m, _ := wire.Decode(s.data)
			out = append(out, m)
		}
	}
	return out
}

func (c *fakeConn) binaries() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, s := range c.out {
		if s.binary {
			n++
		}
	}
	return n
}

func (c *fakeConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

type fakeHelper struct {
	events chan Event
	mu     sync.Mutex
	got    []wire.Msg
	closes int
}

func newHelper() *fakeHelper { return &fakeHelper{events: make(chan Event, 32)} }

func (h *fakeHelper) Events() <-chan Event { return h.events }

func (h *fakeHelper) Send(m wire.Msg) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closes > 0 {
		return errors.New("closed")
	}
	h.got = append(h.got, m)
	return nil
}

func (h *fakeHelper) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closes++
	return nil
}

func (h *fakeHelper) emit(m wire.Msg) { h.events <- Event{Kind: wire.KindJSON, Data: wire.Encode(m)} }
func (h *fakeHelper) tile() {
	h.events <- Event{Kind: wire.KindTile, Data: wire.AppendTile(nil, wire.Tile{W: 1, H: 1}, []byte{1})}
}
func (h *fakeHelper) allow() { h.emit(wire.Msg{T: "consent", Allow: wire.Bool(true)}) }
func (h *fakeHelper) received() []wire.Msg {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]wire.Msg(nil), h.got...)
}

func (h *fakeHelper) closed() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.closes
}

type fakePlatform struct {
	preflight error
	launch    error
	helper    *fakeHelper
	watch     chan string
	mu        sync.Mutex
	sas       int
	launched  int
}

func (p *fakePlatform) Preflight(context.Context) error { return p.preflight }
func (p *fakePlatform) Launch(context.Context, Params) (Helper, error) {
	p.launched++
	if p.launch != nil {
		return nil, p.launch
	}
	return p.helper, nil
}
func (p *fakePlatform) Watch(context.Context) <-chan string { return p.watch }
func (p *fakePlatform) SendSAS() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sas++
	return nil
}

func (p *fakePlatform) sasCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sas
}

func params(mode string) Params {
	return Params{SessionID: strings.Repeat("a", 32), Token: strings.Repeat("t", 43), Mode: mode,
		RequesterEmail: "it@example.com", Reason: "frozen Outlook", ConsentTimeout: time.Minute,
		IdleTimeout: time.Hour, MaxDuration: time.Hour, MaxFPS: 15}
}

type rig struct {
	c      *Controller
	conn   *fakeConn
	helper *fakeHelper
	plat   *fakePlatform
	dials  int
}

func newRig() *rig {
	r := &rig{conn: newConn(), helper: newHelper()}
	r.plat = &fakePlatform{helper: r.helper, watch: make(chan string, 1)}
	r.c = New(r.plat, func(context.Context, string, string) (Conn, error) {
		r.dials++
		return r.conn, nil
	})
	r.c.Tick = 5 * time.Millisecond
	return r
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func hasMsg(ms []wire.Msg, typ, reason string) bool {
	for _, m := range ms {
		if m.T == typ && (reason == "" || m.Reason == reason) {
			return true
		}
	}
	return false
}

func (r *rig) waitOver(t *testing.T) {
	t.Helper()
	done := make(chan struct{})
	go func() { r.c.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("session did not end")
	}
	if r.helper.closed() == 0 {
		t.Fatal("helper was not closed: it would be left running")
	}
	if !r.conn.isClosed() {
		t.Fatal("relay socket left open")
	}
	if r.c.Busy() {
		t.Fatal("controller still busy")
	}
}

// --- tests -------------------------------------------------------------------

func TestNoAttendedUserFailsBeforeDialing(t *testing.T) {
	r := newRig()
	r.plat.preflight = Errorf(ErrNoAttendedUser, "the screen is locked")
	res := r.c.Start(context.Background(), params("view"))
	if res.Status != "failed" || res.ErrorCode != ErrNoAttendedUser {
		t.Fatalf("got %+v", res)
	}
	if r.dials != 0 || r.plat.launched != 0 || r.c.Busy() {
		t.Fatal("nothing may be dialled or launched without an attended user")
	}
}

func TestOnlyOneSessionAtATime(t *testing.T) {
	r := newRig()
	if res := r.c.Start(context.Background(), params("view")); res.Status != "succeeded" {
		t.Fatalf("got %+v", res)
	}
	if res := r.c.Start(context.Background(), params("view")); res.ErrorCode != ErrBusy {
		t.Fatalf("second start: %+v", res)
	}
	r.conn.server(wire.Msg{T: "end", Reason: "ended_by_viewer"})
	r.waitOver(t)
}

func TestDialFailureNeverStartsTheHelper(t *testing.T) {
	r := newRig()
	r.c.Dial = func(context.Context, string, string) (Conn, error) { return nil, errors.New("x509: unknown authority") }
	res := r.c.Start(context.Background(), params("view"))
	if res.ErrorCode != ErrConnect || r.plat.launched != 0 || r.c.Busy() {
		t.Fatalf("got %+v launched=%d", res, r.plat.launched)
	}
}

func TestHelperLaunchFailureIsReported(t *testing.T) {
	r := newRig()
	r.plat.launch = Errorf(ErrHelper, "CreateProcessAsUser: access denied")
	res := r.c.Start(context.Background(), params("view"))
	if res.ErrorCode != ErrHelper {
		t.Fatalf("got %+v", res)
	}
	if !hasMsg(r.conn.msgs(), "error", "") || !r.conn.isClosed() {
		t.Fatal("the relay must hear about the failure and be closed")
	}
}

func TestViewOnlyDropsInput(t *testing.T) {
	r := newRig()
	r.c.Start(context.Background(), params("view"))
	r.helper.allow()
	eventually(t, "consent forwarded", func() bool { return hasMsg(r.conn.msgs(), "consent", "") })
	x := 0.5
	r.conn.server(wire.Msg{T: "input", Kind: "move", X: &x, Y: &x})
	r.conn.server(wire.Msg{T: "input", Kind: "key", Code: "KeyA", Down: wire.Bool(true)})
	r.conn.server(wire.Msg{T: "cad"})
	seq := uint32(1)
	r.conn.server(wire.Msg{T: "ack", Seq: &seq})
	eventually(t, "ack forwarded", func() bool { return hasMsg(r.helper.received(), "ack", "") })
	for _, m := range r.helper.received() {
		if m.T == "input" {
			t.Fatal("input reached the helper in View only mode")
		}
	}
	if r.plat.sasCount() != 0 {
		t.Fatal("Ctrl+Alt+Del sent in View only mode")
	}
	r.conn.server(wire.Msg{T: "end", Reason: "ended_by_viewer"})
	r.waitOver(t)
}

func TestControlForwardsInputAndCAD(t *testing.T) {
	r := newRig()
	r.c.Start(context.Background(), params("control"))
	// Input before consent is dropped even in control mode.
	r.conn.server(wire.Msg{T: "input", Kind: "key", Code: "KeyA", Down: wire.Bool(true)})
	time.Sleep(30 * time.Millisecond) // processed (and dropped) before the user answers
	r.helper.allow()
	eventually(t, "consent forwarded", func() bool { return hasMsg(r.conn.msgs(), "consent", "") })
	r.conn.server(wire.Msg{T: "input", Kind: "key", Code: "KeyB", Down: wire.Bool(true)})
	r.conn.server(wire.Msg{T: "cad"})
	eventually(t, "input forwarded", func() bool { return len(r.helper.received()) == 1 })
	if got := r.helper.received()[0]; got.Code != "KeyB" {
		t.Fatalf("forwarded %+v", got)
	}
	eventually(t, "SAS", func() bool { return r.plat.sasCount() == 1 })
	r.conn.server(wire.Msg{T: "end"})
	r.waitOver(t)
}

func TestNoFramesBeforeConsent(t *testing.T) {
	r := newRig()
	r.c.Start(context.Background(), params("view"))
	r.helper.tile()
	r.helper.allow()
	r.helper.tile()
	eventually(t, "frame after consent", func() bool { return r.conn.binaries() == 1 })
	time.Sleep(20 * time.Millisecond)
	if n := r.conn.binaries(); n != 1 {
		t.Fatalf("%d frames sent, want only the one after consent", n)
	}
	r.conn.server(wire.Msg{T: "end"})
	r.waitOver(t)
}

func TestUserEndsSession(t *testing.T) {
	r := newRig()
	r.c.Start(context.Background(), params("control"))
	r.helper.allow()
	r.helper.emit(wire.Msg{T: "ended", Reason: "user_ended"})
	r.waitOver(t)
	if !hasMsg(r.conn.msgs(), "ended", "user_ended") {
		t.Fatalf("server not told: %+v", r.conn.msgs())
	}
}

func TestIndicatorClosedEndsSession(t *testing.T) {
	r := newRig()
	r.c.Start(context.Background(), params("view"))
	r.helper.allow()
	r.helper.emit(wire.Msg{T: "ended", Reason: "indicator_closed"})
	r.waitOver(t)
	if !hasMsg(r.conn.msgs(), "ended", "indicator_closed") {
		t.Fatal("indicator_closed not reported")
	}
}

func TestUserDenies(t *testing.T) {
	r := newRig()
	r.c.Start(context.Background(), params("view"))
	r.helper.emit(wire.Msg{T: "consent", Allow: wire.Bool(false)})
	r.waitOver(t)
	ms := r.conn.msgs()
	if len(ms) != 1 || ms[0].T != "consent" || *ms[0].Allow || ms[0].Reason != "" {
		t.Fatalf("got %+v", ms)
	}
}

func TestConsentTimeoutIsDenied(t *testing.T) {
	r := newRig()
	r.c.ConsentGrace = 0
	p := params("view")
	p.ConsentTimeout = 30 * time.Millisecond
	r.c.Start(context.Background(), p) // the helper never answers
	r.waitOver(t)
	ms := r.conn.msgs()
	if len(ms) == 0 || ms[0].T != "consent" || *ms[0].Allow || ms[0].Reason != "timeout" {
		t.Fatalf("got %+v", ms)
	}
}

func TestIdleLimit(t *testing.T) {
	r := newRig()
	p := params("view")
	p.IdleTimeout = 40 * time.Millisecond
	r.c.Start(context.Background(), p)
	r.helper.allow()
	r.waitOver(t)
	if !hasMsg(r.conn.msgs(), "ended", "idle") {
		t.Fatalf("got %+v", r.conn.msgs())
	}
}

func TestActivityKeepsTheSessionAndHardLimitStillFires(t *testing.T) {
	r := newRig()
	p := params("view")
	p.IdleTimeout, p.MaxDuration = 60*time.Millisecond, 200*time.Millisecond
	r.c.Start(context.Background(), p)
	r.helper.allow()
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(15 * time.Millisecond):
				r.conn.server(wire.Msg{T: "activity"})
			}
		}
	}()
	r.waitOver(t)
	close(stop)
	if !hasMsg(r.conn.msgs(), "ended", "max_duration") {
		t.Fatalf("got %+v", r.conn.msgs())
	}
}

func TestServerUnreachableStopsHelperAtOnce(t *testing.T) {
	r := newRig()
	r.c.Start(context.Background(), params("control"))
	r.helper.allow()
	eventually(t, "consent forwarded", func() bool { return hasMsg(r.conn.msgs(), "consent", "") })
	r.conn.hangUp()
	r.waitOver(t)
}

func TestAgentStoppingEndsSession(t *testing.T) {
	r := newRig()
	ctx, cancel := context.WithCancel(context.Background())
	r.c.Start(ctx, params("view"))
	r.helper.allow()
	eventually(t, "consent forwarded", func() bool { return hasMsg(r.conn.msgs(), "consent", "") })
	cancel()
	r.waitOver(t)
	if !hasMsg(r.conn.msgs(), "ended", "agent_stopping") {
		t.Fatalf("got %+v", r.conn.msgs())
	}
}

func TestSessionSwitchEndsSession(t *testing.T) {
	r := newRig()
	r.c.Start(context.Background(), params("view"))
	r.helper.allow()
	r.plat.watch <- "session_switch"
	r.waitOver(t)
	if !hasMsg(r.conn.msgs(), "ended", "session_switch") {
		t.Fatalf("got %+v", r.conn.msgs())
	}
}

func TestHelperExitEndsSession(t *testing.T) {
	r := newRig()
	r.c.Start(context.Background(), params("view"))
	r.helper.allow()
	close(r.helper.events)
	r.waitOver(t)
	if !hasMsg(r.conn.msgs(), "ended", "helper_exit") {
		t.Fatalf("got %+v", r.conn.msgs())
	}
}

func TestParseParams(t *testing.T) {
	good := MarshalParams(params("control"))
	p, err := ParseParams(good)
	if err != nil || p.Mode != "control" || !p.Control() || p.MaxFPS != 15 {
		t.Fatalf("%+v %v", p, err)
	}
	if wp := p.WireParams(); wp.SessionID != p.SessionID || wp.ConsentSeconds != 60 {
		t.Fatalf("wire params %+v", wp)
	}
	// A server cannot stretch the local limits.
	over := MarshalParams(params("view"))
	over["max_duration_seconds"], over["idle_timeout_seconds"], over["max_fps"] = 999999.0, 999999.0, 240.0
	p, err = ParseParams(over)
	if err != nil || p.MaxDuration != MaxDuration || p.IdleTimeout != MaxIdleTimeout || p.MaxFPS != MaxFPS {
		t.Fatalf("not capped: %+v %v", p, err)
	}
	for name, mut := range map[string]func(map[string]any){
		"mode":       func(m map[string]any) { m["mode"] = "unattended" },
		"session id": func(m map[string]any) { m["session_id"] = "../../etc" },
		"token":      func(m map[string]any) { m["token"] = "short" },
		"no token":   func(m map[string]any) { delete(m, "token") },
		"reason":     func(m map[string]any) { m["reason"] = "" },
		"control":    func(m map[string]any) { m["requester_name"] = "a\x07b" },
		"long":       func(m map[string]any) { m["reason"] = strings.Repeat("x", 501) },
		"fps":        func(m map[string]any) { m["max_fps"] = 1.5 },
	} {
		m := MarshalParams(params("view"))
		mut(m)
		if _, err := ParseParams(m); err == nil {
			t.Errorf("%s: accepted %v", name, m)
		}
	}
}

func TestRelayURL(t *testing.T) {
	sid := strings.Repeat("b", 32)
	u, err := relayURL("https://console.example.com/", sid, false)
	if err != nil || u != "wss://console.example.com/api/agent/remote/"+sid {
		t.Fatalf("%q %v", u, err)
	}
	if _, err := relayURL("http://localhost:8000", sid, false); err == nil {
		t.Fatal("plain ws:// accepted without --insecure-dev")
	}
	if u, _ := relayURL("http://localhost:8000", sid, true); u != "ws://localhost:8000/api/agent/remote/"+sid {
		t.Fatalf("dev url %q", u)
	}
	if _, err := relayURL("https://console.example.com", "x/../y", false); err == nil {
		t.Fatal("invalid session id accepted")
	}
}

// The helper runs as the user: only known end reasons and error codes reach
// the server, and its detail text is cut short.
func TestHelperTextIsAllowlistedAndTruncated(t *testing.T) {
	r := newRig()
	r.c.Start(context.Background(), params("view"))
	r.helper.allow()
	r.helper.emit(wire.Msg{T: "ended", Reason: "ended_by_admin\nforged"})
	r.waitOver(t)
	if !hasMsg(r.conn.msgs(), "ended", "helper_exit") || hasMsg(r.conn.msgs(), "ended", "ended_by_admin\nforged") {
		t.Fatalf("unknown reason forwarded: %+v", r.conn.msgs())
	}

	r = newRig()
	r.c.Start(context.Background(), params("view"))
	r.helper.allow()
	r.helper.emit(wire.Msg{T: "monitors", Monitors: []wire.Monitor{{W: 10, H: 10}}, Params: &wire.Params{Mode: "control"},
		Reason: "x", Detail: "y"})
	r.helper.emit(wire.Msg{T: "error", Code: "ERR_FORGED", Detail: strings.Repeat("é", 300) + "\x1b[2J"})
	r.waitOver(t)
	var errMsg, mons *wire.Msg
	for _, m := range r.conn.msgs() {
		m := m
		switch m.T {
		case "error":
			errMsg = &m
		case "monitors":
			mons = &m
		}
	}
	if errMsg == nil || errMsg.Code != ErrHelper || utf8.RuneCountInString(errMsg.Detail) != 200 ||
		strings.ContainsRune(errMsg.Detail, 0x1b) {
		t.Fatalf("error forwarded as %+v", errMsg)
	}
	if mons == nil || mons.Params != nil || mons.Reason != "" || mons.Detail != "" || len(mons.Monitors) != 1 {
		t.Fatalf("monitors forwarded as %+v", mons)
	}
}
