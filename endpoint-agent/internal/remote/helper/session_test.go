package helper

import (
	"context"
	"image"
	"sync"
	"testing"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/remote/wire"
)

type fakeUI struct {
	answer    *bool // nil: never answers
	indicator chan string
	mu        sync.Mutex
	closed    bool
	exclude   image.Rectangle
}

func (u *fakeUI) Consent(ctx context.Context, _ wire.Params) bool {
	if u.answer == nil {
		<-ctx.Done()
		return false
	}
	return *u.answer
}
func (u *fakeUI) ShowIndicator(wire.Params) <-chan string { return u.indicator }
func (u *fakeUI) Excluded(x, y int) bool                  { return image.Pt(x, y).In(u.exclude) }
func (u *fakeUI) Close() {
	u.mu.Lock()
	u.closed = true
	u.mu.Unlock()
}

type fakeCapturer struct {
	mu       sync.Mutex
	closed   bool
	grabs    int
	after    int // grabs after Close (must stay 0)
	protect  bool
	frameVal byte
}

func (c *fakeCapturer) Monitors() ([]wire.Monitor, error) {
	return []wire.Monitor{{ID: 0, W: 128, H: 64, Scale: 1, Primary: true},
		{ID: 1, X: 128, W: 64, H: 64, Scale: 1.5}}, nil
}

func (c *fakeCapturer) Grab(m wire.Monitor) (*Frame, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.grabs++
	if c.closed {
		c.after++
	}
	if c.protect {
		return nil, true, nil
	}
	f := &Frame{W: m.W, H: m.H, Stride: m.W * 4, Pix: make([]byte, m.W*m.H*4)}
	for i := range f.Pix {
		f.Pix[i] = c.frameVal
	}
	return f, false, nil
}

func (c *fakeCapturer) Close() {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
}

type fakeInjector struct {
	mu  sync.Mutex
	got []wire.Msg
	pos [][2]int
}

func (i *fakeInjector) Inject(m wire.Msg, x, y int, ok bool) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.got = append(i.got, m)
	i.pos = append(i.pos, [2]int{x, y})
	return nil
}

func (i *fakeInjector) count() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return len(i.got)
}

type fakeLink struct {
	recv  chan wire.Msg
	mu    sync.Mutex
	sent  []wire.Msg
	tiles [][]byte
}

func newLink() *fakeLink { return &fakeLink{recv: make(chan wire.Msg, 16)} }

func (l *fakeLink) Recv() <-chan wire.Msg { return l.recv }
func (l *fakeLink) Send(m wire.Msg) error {
	l.mu.Lock()
	l.sent = append(l.sent, m)
	l.mu.Unlock()
	return nil
}
func (l *fakeLink) SendTile(b []byte) error {
	l.mu.Lock()
	l.tiles = append(l.tiles, b)
	l.mu.Unlock()
	return nil
}
func (l *fakeLink) types() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var t []string
	for _, m := range l.sent {
		t = append(t, m.T)
	}
	return t
}
func (l *fakeLink) tileCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.tiles)
}

func yes() *bool { v := true; return &v }
func no() *bool  { v := false; return &v }

func params(mode string) wire.Params {
	return wire.Params{SessionID: "s", Mode: mode, RequesterEmail: "it@example.com", ConsentSeconds: 60, MaxFPS: 30}
}

type run struct {
	link   *fakeLink
	ui     *fakeUI
	capt   *fakeCapturer
	inj    *fakeInjector
	reason chan string
}

func start(t *testing.T, mode string, answer *bool) *run {
	t.Helper()
	r := &run{link: newLink(), ui: &fakeUI{answer: answer, indicator: make(chan string, 1)},
		capt: &fakeCapturer{}, inj: &fakeInjector{}, reason: make(chan string, 1)}
	p := params(mode)
	go func() {
		r.reason <- RunSession(context.Background(), r.link, p, r.ui, r.capt, r.inj, Options{Tile: 32})
	}()
	return r
}

func (r *run) wait(t *testing.T) string {
	t.Helper()
	select {
	case why := <-r.reason:
		return why
	case <-time.After(3 * time.Second):
		t.Fatal("session did not end")
		return ""
	}
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

func fp(v float64) *float64 { return &v }

func TestDenyCapturesNothing(t *testing.T) {
	r := start(t, "control", no())
	if why := r.wait(t); why != "denied" {
		t.Fatalf("ended with %q", why)
	}
	if r.capt.grabs != 0 || r.link.tileCount() != 0 {
		t.Fatal("captured before consent")
	}
	if got := r.link.types(); len(got) != 1 || got[0] != "consent" || *r.link.sent[0].Allow {
		t.Fatalf("sent %v", got)
	}
}

func TestConsentTimeout(t *testing.T) {
	r := &run{link: newLink(), ui: &fakeUI{indicator: make(chan string, 1)}, capt: &fakeCapturer{},
		inj: &fakeInjector{}, reason: make(chan string, 1)}
	p := params("view")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p.ConsentSeconds = 0 // falls back to 60 s: use a short parent context instead
	go func() {
		short, c := context.WithTimeout(ctx, 30*time.Millisecond)
		defer c()
		r.reason <- RunSession(short, r.link, p, r.ui, r.capt, r.inj, Options{})
	}()
	if why := r.wait(t); why != "denied" && why != "consent_timeout" {
		t.Fatalf("ended with %q", why)
	}
	if r.link.sent[0].T != "consent" || *r.link.sent[0].Allow {
		t.Fatalf("sent %+v", r.link.sent)
	}
}

func TestEndSessionStopsCaptureFirst(t *testing.T) {
	r := start(t, "control", yes())
	eventually(t, "frames", func() bool { return r.link.tileCount() > 0 })
	r.ui.indicator <- "user_ended"
	if why := r.wait(t); why != "user_ended" {
		t.Fatalf("ended with %q", why)
	}
	types := r.link.types()
	if types[len(types)-1] != "ended" {
		t.Fatalf("last message %v", types)
	}
	r.capt.mu.Lock()
	defer r.capt.mu.Unlock()
	if !r.capt.closed || r.capt.after != 0 || !r.ui.closed {
		t.Fatalf("capture not stopped: closed=%v grabs after close=%d ui closed=%v", r.capt.closed, r.capt.after, r.ui.closed)
	}
}

func TestIndicatorClosedEndsSession(t *testing.T) {
	r := start(t, "view", yes())
	eventually(t, "started", func() bool {
		for _, ty := range r.link.types() {
			if ty == "started" {
				return true
			}
		}
		return false
	})
	r.ui.indicator <- "indicator_closed"
	if why := r.wait(t); why != "indicator_closed" {
		t.Fatalf("ended with %q", why)
	}
	if m := r.link.sent[len(r.link.sent)-1]; m.T != "ended" || m.Reason != "indicator_closed" {
		t.Fatalf("last %+v", m)
	}
}

func TestViewOnlyDropsInputInTheHelperToo(t *testing.T) {
	r := start(t, "view", yes())
	eventually(t, "frames", func() bool { return r.link.tileCount() > 0 })
	r.link.recv <- wire.Msg{T: "input", Kind: "move", X: fp(0.5), Y: fp(0.5)}
	r.link.recv <- wire.Msg{T: "input", Kind: "key", Code: "KeyA", Down: yes()}
	time.Sleep(30 * time.Millisecond)
	if n := r.inj.count(); n != 0 {
		t.Fatalf("%d input events injected in View only mode", n)
	}
	r.link.recv <- wire.Msg{T: "stop"}
	if why := r.wait(t); why != "stopped" {
		t.Fatalf("ended with %q", why)
	}
}

func TestControlInjectsAtMonitorCoordinatesButNeverOnTheIndicator(t *testing.T) {
	r := start(t, "control", yes())
	r.ui.mu.Lock()
	r.ui.exclude = image.Rect(150, 0, 192, 10) // the indicator, on monitor 1
	r.ui.mu.Unlock()
	eventually(t, "frames", func() bool { return r.link.tileCount() > 0 })
	r.link.recv <- wire.Msg{T: "input", Kind: "move", X: fp(1), Y: fp(1)} // bottom-right of monitor 0
	id := 1
	r.link.recv <- wire.Msg{T: "select_monitor", ID: &id}
	r.link.recv <- wire.Msg{T: "input", Kind: "button", Button: new(int), Down: yes(), X: fp(0.5), Y: fp(0.05)}
	r.link.recv <- wire.Msg{T: "input", Kind: "move", X: fp(0), Y: fp(0.5)}
	eventually(t, "two injected", func() bool { return r.inj.count() == 2 })
	r.inj.mu.Lock()
	pos := append([][2]int(nil), r.inj.pos...)
	r.inj.mu.Unlock()
	if pos[0] != [2]int{127, 63} || pos[1] != [2]int{128, 32} {
		t.Fatalf("positions %v", pos)
	}
	r.link.recv <- wire.Msg{T: "stop"}
	r.wait(t)
}

func TestProtectedDesktopIsReported(t *testing.T) {
	r := start(t, "view", yes())
	eventually(t, "frames", func() bool { return r.link.tileCount() > 0 })
	r.capt.mu.Lock()
	r.capt.protect = true
	r.capt.mu.Unlock()
	eventually(t, "protected", func() bool {
		r.link.mu.Lock()
		defer r.link.mu.Unlock()
		for _, m := range r.link.sent {
			if m.T == "protected" && m.On != nil && *m.On {
				return true
			}
		}
		return false
	})
	r.link.recv <- wire.Msg{T: "stop"}
	r.wait(t)
}

func TestServiceGoneEndsSession(t *testing.T) {
	r := start(t, "view", yes())
	eventually(t, "frames", func() bool { return r.link.tileCount() > 0 })
	close(r.link.recv)
	if why := r.wait(t); why != "service_gone" {
		t.Fatalf("ended with %q", why)
	}
	if !r.capt.closed {
		t.Fatal("capture left running")
	}
}

func TestBackpressurePausesCapture(t *testing.T) {
	r := start(t, "view", yes())
	r.capt.mu.Lock()
	r.capt.frameVal = 1
	r.capt.mu.Unlock()
	eventually(t, "frames", func() bool { return r.link.tileCount() > 0 })
	// Change the image every grab; without acks at most MaxUnacked (3) frames go out.
	for i := 0; i < 10; i++ {
		r.capt.mu.Lock()
		r.capt.frameVal++
		r.capt.mu.Unlock()
		time.Sleep(40 * time.Millisecond)
	}
	r.link.mu.Lock()
	seqs := map[uint32]bool{}
	for _, b := range r.link.tiles {
		tl, _, _ := wire.ParseTile(b)
		seqs[tl.Seq] = true
	}
	r.link.mu.Unlock()
	if len(seqs) > 3 {
		t.Fatalf("%d frames without acks", len(seqs))
	}
	r.link.recv <- wire.Msg{T: "stop"}
	r.wait(t)
}

func (i *fakeInjector) snapshot() ([]wire.Msg, [][2]int) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return append([]wire.Msg(nil), i.got...), append([][2]int(nil), i.pos...)
}

// Whatever the viewer still holds when the session stops (tab closed, network
// gone, End session) is released: nothing stays stuck down on the desktop.
func TestHeldKeysAndButtonsAreReleasedWhenTheSessionStops(t *testing.T) {
	r := start(t, "control", yes())
	eventually(t, "frames", func() bool { return r.link.tileCount() > 0 })
	right := 2
	r.link.recv <- wire.Msg{T: "input", Kind: "key", Code: "ControlLeft", Down: yes()}
	r.link.recv <- wire.Msg{T: "input", Kind: "key", Code: "KeyC", Down: yes()}
	r.link.recv <- wire.Msg{T: "input", Kind: "key", Code: "KeyC", Down: no()}
	r.link.recv <- wire.Msg{T: "input", Kind: "button", Button: &right, Down: yes(), X: fp(0.5), Y: fp(0.5)}
	eventually(t, "four injected", func() bool { return r.inj.count() == 4 })
	r.link.recv <- wire.Msg{T: "stop"}
	r.wait(t)
	got, pos := r.inj.snapshot()
	if len(got) != 6 {
		t.Fatalf("injected %d, want 6 (2 releases): %+v", len(got), got)
	}
	key, btn := got[4], got[5]
	if key.Kind != "key" || key.Code != "ControlLeft" || key.Down == nil || *key.Down {
		t.Fatalf("key release %+v", key)
	}
	if btn.Kind != "button" || btn.Button == nil || *btn.Button != 2 || btn.Down == nil || *btn.Down ||
		pos[5] != pos[3] {
		t.Fatalf("button release %+v at %v (pressed at %v)", btn, pos[5], pos[3])
	}
}

// A click without a position would land at the user's own cursor (maybe on
// the indicator): dropped. Keys need no position.
func TestClickWithoutPositionIsDropped(t *testing.T) {
	r := start(t, "control", yes())
	eventually(t, "frames", func() bool { return r.link.tileCount() > 0 })
	r.link.recv <- wire.Msg{T: "input", Kind: "button", Button: new(int), Down: yes()}
	r.link.recv <- wire.Msg{T: "input", Kind: "move"}
	r.link.recv <- wire.Msg{T: "input", Kind: "key", Code: "KeyA", Down: yes()}
	eventually(t, "the key", func() bool { return r.inj.count() == 1 })
	time.Sleep(20 * time.Millisecond)
	if got, _ := r.inj.snapshot(); len(got) != 1 || got[0].Kind != "key" {
		t.Fatalf("injected %+v", got)
	}
	r.link.recv <- wire.Msg{T: "stop"}
	r.wait(t)
}

// A drag that ends over the indicator still releases the button, where the
// viewer last was (never on the indicator itself).
func TestButtonReleasedOverTheIndicatorIsNotLost(t *testing.T) {
	r := start(t, "control", yes())
	r.ui.mu.Lock()
	r.ui.exclude = image.Rect(0, 0, 40, 10)
	r.ui.mu.Unlock()
	eventually(t, "frames", func() bool { return r.link.tileCount() > 0 })
	r.link.recv <- wire.Msg{T: "input", Kind: "button", Button: new(int), Down: yes(), X: fp(0.5), Y: fp(0.5)}
	r.link.recv <- wire.Msg{T: "input", Kind: "move", X: fp(0.1), Y: fp(0.02)} // onto the indicator: dropped
	r.link.recv <- wire.Msg{T: "input", Kind: "button", Button: new(int), Down: no(), X: fp(0.1), Y: fp(0.02)}
	eventually(t, "down and up", func() bool { return r.inj.count() == 2 })
	r.link.recv <- wire.Msg{T: "stop"}
	r.wait(t)
	got, pos := r.inj.snapshot()
	if len(got) != 2 || *got[1].Down || pos[1] != pos[0] {
		t.Fatalf("injected %+v at %v", got, pos)
	}
}
