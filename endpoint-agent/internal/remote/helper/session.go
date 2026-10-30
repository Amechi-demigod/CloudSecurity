// Package helper is the remote-session helper process: it runs in the signed-in
// user's session (started by the service, `cnapp-agent remote-helper`), shows
// the consent prompt and the always-on-top indicator, captures the screen and,
// in View and control mode, injects the viewer's input.
//
// RunSession holds the rules and is platform independent (unit-tested with
// fakes); the Windows UI, capture (DXGI Desktop Duplication, GDI fallback) and
// SendInput backends live in the _windows files.
//
//   - Nothing is captured before the user clicks Allow; Deny or no answer in
//     time ends the session.
//   - End session (indicator) stops capture and input first, then tells the
//     service; it needs no server.
//   - The indicator cannot be dismissed by the viewer: its windows never take
//     focus (injected keys such as Alt+F4 never reach them), injected clicks
//     on them are dropped, and if it is closed or destroyed anyway the
//     session ends (it is never silently re-created).
//   - Input is dropped in View only mode, whatever the service sends. Clicks
//     need a position (never "wherever the user's cursor is"), and every key
//     and button the viewer pressed is released when the session stops.
package helper

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/remote/wire"
)

// UI is the consent prompt and the indicator.
type UI interface {
	// Consent shows the prompt until the user answers or ctx ends (no answer).
	Consent(ctx context.Context, p wire.Params) (allow bool)
	// ShowIndicator shows "IT support (name) is viewing / controlling your
	// screen" with End session. The channel receives "user_ended" (End
	// session) or "indicator_closed" (the window went away).
	ShowIndicator(p wire.Params) <-chan string
	// Excluded: the screen point (virtual-desktop pixels) is on the prompt or
	// the indicator; injected clicks there are dropped.
	Excluded(x, y int) bool
	Close()
}

// Capturer grabs monitors.
type Capturer interface {
	Monitors() ([]wire.Monitor, error)
	// Grab returns the monitor's current image. protected is true while the
	// user's desktop is not the input desktop (UAC secure desktop, sign-in).
	Grab(m wire.Monitor) (f *Frame, protected bool, err error)
	Close()
}

// Injector replays input on the user's desktop.
type Injector interface {
	// Inject replays one input message; (x, y) are resolved to the virtual
	// desktop already (ok=false for messages without a position).
	Inject(m wire.Msg, x, y int, ok bool) error
}

// Link is the pipe to the service.
type Link interface {
	Recv() <-chan wire.Msg // closed when the service goes away
	Send(m wire.Msg) error
	SendTile(b []byte) error
}

// Options tune RunSession (tests shorten them).
type Options struct {
	Tile       int // tile edge in pixels
	MaxUnacked int // frames in flight before capture pauses
}

// RunSession runs one session and returns why it ended.
func RunSession(ctx context.Context, link Link, p wire.Params, ui UI, capt Capturer, inj Injector, o Options) string {
	if o.Tile == 0 {
		o.Tile = 64
	}
	if o.MaxUnacked == 0 {
		o.MaxUnacked = 3
	}
	consentFor := time.Duration(p.ConsentSeconds) * time.Second
	if consentFor <= 0 || consentFor > 5*time.Minute {
		consentFor = 60 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, consentFor)
	allow := ui.Consent(cctx, p)
	timedOut := cctx.Err() == context.DeadlineExceeded
	cancel()
	if !allow {
		reason := ""
		if timedOut {
			reason = "timeout"
		}
		_ = link.Send(wire.Msg{T: "consent", Allow: wire.Bool(false), Reason: reason})
		ui.Close()
		if reason == "timeout" {
			return "consent_timeout"
		}
		return "denied"
	}
	_ = link.Send(wire.Msg{T: "consent", Allow: wire.Bool(true)})
	s := &state{link: link, p: p, ui: ui, capt: capt, inj: inj, o: o, quality: 70}
	defer s.stop()
	if err := s.loadMonitors(); err != nil {
		_ = link.Send(wire.Msg{T: "error", Code: "ERR_HELPER", Detail: "no monitor to capture: " + err.Error()})
		return "error"
	}
	indicator := ui.ShowIndicator(p)
	_ = link.Send(wire.Msg{T: "started"})
	fps := p.MaxFPS
	if fps <= 0 || fps > 30 {
		fps = 15
	}
	tick := time.NewTicker(time.Second / time.Duration(fps))
	defer tick.Stop()
	recv := link.Recv()
	for {
		select {
		case <-ctx.Done():
			return "helper_stopping"
		case reason := <-indicator:
			// End session: stop capture and input first, then tell the service.
			s.stop()
			_ = link.Send(wire.Msg{T: "ended", Reason: reason})
			return reason
		case m, ok := <-recv:
			if !ok {
				return "service_gone"
			}
			if m.T == "stop" {
				return "stopped"
			}
			s.handle(m)
		case <-tick.C:
			if err := s.frame(); err != nil {
				slog.Warn("capture failed", "err", err)
			}
		}
	}
}

type state struct {
	link Link
	p    wire.Params
	ui   UI
	capt Capturer
	inj  Injector
	o    Options

	stopped   bool
	monitors  []wire.Monitor
	active    int
	prev      *Frame
	seq       uint32
	acked     uint32
	quality   int
	protected bool
	okSince   time.Time
	dropped   int

	// Held down by the viewer (released by stop): keys by KeyboardEvent.code, mouse buttons.
	keys    map[string]bool
	buttons map[int]bool
	// The last position input was injected at (where a release goes).
	lastX, lastY int
	hasPos       bool
}

// stop is idempotent: from here on no frame is captured and no input injected.
// Keys and buttons the viewer still holds are released first, so nothing stays
// stuck down on the user's desktop (a Ctrl held when the viewer's tab closed).
func (s *state) stop() {
	if s.stopped {
		return
	}
	s.releaseAll()
	s.stopped = true
	s.capt.Close()
	s.ui.Close()
}

func (s *state) releaseAll() {
	up := wire.Bool(false)
	for code := range s.keys {
		if err := s.inj.Inject(wire.Msg{T: "input", Kind: "key", Code: code, Down: up}, 0, 0, false); err != nil {
			slog.Debug("key not released", "err", err)
		}
	}
	for b := range s.buttons {
		if !s.hasPos {
			break
		}
		btn := b
		if err := s.inj.Inject(wire.Msg{T: "input", Kind: "button", Button: &btn, Down: up},
			s.lastX, s.lastY, true); err != nil {
			slog.Debug("mouse button not released", "err", err)
		}
	}
	s.keys, s.buttons = nil, nil
}

// track records what the viewer holds down after a successful injection.
func (s *state) track(m wire.Msg, x, y int, ok bool) {
	if ok {
		s.lastX, s.lastY, s.hasPos = x, y, true
	}
	if m.Down == nil {
		return
	}
	switch {
	case m.Kind == "key" && m.Code != "":
		if s.keys == nil {
			s.keys = map[string]bool{}
		}
		if *m.Down {
			s.keys[m.Code] = true
		} else {
			delete(s.keys, m.Code)
		}
	case m.Kind == "button" && m.Button != nil:
		if s.buttons == nil {
			s.buttons = map[int]bool{}
		}
		if *m.Down {
			s.buttons[*m.Button] = true
		} else {
			delete(s.buttons, *m.Button)
		}
	}
}

func (s *state) loadMonitors() error {
	mons, err := s.capt.Monitors()
	if err != nil {
		return err
	}
	if len(mons) == 0 {
		return errNoMonitor
	}
	s.monitors = mons
	if s.active >= len(mons) {
		s.active = 0
	}
	for i, m := range mons {
		if m.Primary && s.prev == nil {
			s.active = i
		}
	}
	active := s.active
	return s.link.Send(wire.Msg{T: "monitors", Monitors: mons, Active: &active})
}

func (s *state) handle(m wire.Msg) {
	if s.stopped {
		return
	}
	switch m.T {
	case "input":
		if s.p.Mode != "control" {
			s.dropped++
			return
		}
		x, y, ok := s.resolve(m)
		if !ok && (m.Kind == "button" || m.Kind == "move") {
			// A click without a position would land wherever the user's cursor
			// is, possibly on the indicator: never.
			s.dropped++
			return
		}
		if ok && s.ui.Excluded(x, y) {
			// The prompt / indicator only answer the user's own clicks. A held
			// button is still released, where the viewer last was.
			if m.Kind == "button" && m.Button != nil && m.Down != nil && !*m.Down && s.buttons[*m.Button] && s.hasPos {
				x, y = s.lastX, s.lastY
			} else {
				s.dropped++
				return
			}
		}
		if err := s.inj.Inject(m, x, y, ok); err != nil {
			slog.Debug("input not injected", "err", err)
			return
		}
		s.track(m, x, y, ok)
	case "select_monitor":
		if m.ID != nil && *m.ID >= 0 && *m.ID < len(s.monitors) {
			s.active, s.prev = *m.ID, nil
			active := s.active
			_ = s.link.Send(wire.Msg{T: "monitors", Monitors: s.monitors, Active: &active})
		}
	case "ack":
		if m.Seq != nil && *m.Seq > s.acked && *m.Seq <= s.seq {
			s.acked = *m.Seq
		}
	case "quality":
		switch m.Level {
		case "low":
			s.quality = 40
		case "high":
			s.quality = 85
		default:
			s.quality = 70
		}
	}
}

// resolve maps the viewer's (x, y) in [0,1] of the active monitor to
// virtual-desktop pixels.
func (s *state) resolve(m wire.Msg) (int, int, bool) {
	if m.X == nil || m.Y == nil || len(s.monitors) == 0 {
		return 0, 0, false
	}
	mon := s.monitors[s.active]
	fx, fy := clamp01(*m.X), clamp01(*m.Y)
	return mon.X + int(fx*float64(mon.W-1)+0.5), mon.Y + int(fy*float64(mon.H-1)+0.5), true
}

func clamp01(v float64) float64 {
	if v < 0 || v != v {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// frame captures the active monitor and sends the tiles that changed. Capture
// pauses while too many frames are unacknowledged (slow viewer), and the
// JPEG quality adapts: down while frames pile up, slowly back up when not.
func (s *state) frame() error {
	if s.stopped {
		return nil
	}
	if int(s.seq-s.acked) >= s.o.MaxUnacked {
		if s.quality > 35 {
			s.quality -= 5
		}
		s.okSince = time.Time{}
		return nil
	}
	if s.okSince.IsZero() {
		s.okSince = time.Now()
	} else if time.Since(s.okSince) > 3*time.Second && s.quality < 80 {
		s.quality += 5
		s.okSince = time.Now()
	}
	mon := s.monitors[s.active]
	f, protected, err := s.capt.Grab(mon)
	if protected != s.protected {
		s.protected = protected
		_ = s.link.Send(wire.Msg{T: "protected", On: wire.Bool(protected)})
		s.prev = nil
	}
	if err != nil || protected || f == nil {
		return err
	}
	rects := Diff(s.prev, f, s.o.Tile)
	s.prev = f
	if len(rects) == 0 {
		return nil
	}
	s.seq++
	for i, r := range rects {
		jpg, err := EncodeJPEG(f, r, s.quality)
		if err != nil {
			return err
		}
		t := wire.Tile{Monitor: uint8(s.active), X: uint16(r.Min.X), Y: uint16(r.Min.Y),
			W: uint16(r.Dx()), H: uint16(r.Dy()), Seq: s.seq}
		if i == len(rects)-1 {
			t.Flags = wire.TileFlagLast
		}
		if err := s.link.SendTile(wire.AppendTile(nil, t, jpg)); err != nil {
			return err
		}
	}
	return nil
}

var errNoMonitor = errors.New("no monitor found")
