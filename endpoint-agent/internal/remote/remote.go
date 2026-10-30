// Package remote runs attended remote sessions (start_remote_session):
// IT support views, and with "View and control" controls, the signed-in
// user's screen after the user allows it.
//
// The service never captures anything itself. It
//
//  1. checks that someone is signed in and the screen is not locked
//     (ERR_NO_ATTENDED_USER otherwise; ERR_UNSUPPORTED_PLATFORM off Windows),
//  2. dials the relay over WSS - only the enrolled server URL, the pinned CA,
//     its device credential and the single-use session token from the
//     command (which arrived through the normal validated, nonced, device-bound
//     command channel) - and
//  3. starts the helper in the user's session (Platform.Launch), which shows
//     the consent prompt, then the always-on-top indicator, and captures.
//
// The Controller then relays between the socket and the helper and enforces
// the session's rules locally, whatever the server sends: input is dropped in
// View only mode, nothing is sent before the user allowed it, and the consent
// timeout, idle and hard limits end the session. Ending tears the helper down
// first (capture and input stop at once), then tells the server.
//
// Protocol messages are defined in internal/remote/wire and documented in
// backend/app/api/remote_relay.py.
package remote

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/remote/wire"
)

// CommandType is the command this package runs.
const CommandType = "start_remote_session"

// Error codes reported with a failed command result or a relay "error" message.
const (
	ErrNoAttendedUser      = "ERR_NO_ATTENDED_USER"
	ErrUnsupportedPlatform = "ERR_UNSUPPORTED_PLATFORM"
	ErrHelper              = "ERR_HELPER"
	ErrBusy                = "ERR_BUSY"
	ErrConnect             = "ERR_CONNECT"
	ErrInvalid             = "ERR_INVALID"
)

// Local upper bounds: a server cannot keep a session open longer than these,
// whatever it sends (they match the server's own accepted ranges).
const (
	MaxConsentTimeout = 5 * time.Minute
	MaxIdleTimeout    = 2 * time.Hour
	MaxDuration       = 8 * time.Hour
	MaxFPS            = 30
	// The service waits this much longer than the prompt itself before it
	// treats a silent helper as "no answer".
	consentGrace = 10 * time.Second
)

// Error is a failure with a reportable code.
type Error struct {
	Code string
	Msg  string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

// Errorf builds an *Error.
func Errorf(code, format string, a ...any) error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, a...)}
}

// CodeOf returns the code of err (ERR_HELPER for an error without one).
func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ErrHelper
}

// Params of a start_remote_session command.
type Params struct {
	SessionID      string
	Token          string
	Mode           string // view | control
	RequesterName  string
	RequesterEmail string
	OrgName        string
	Reason         string
	ConsentTimeout time.Duration
	IdleTimeout    time.Duration
	MaxDuration    time.Duration
	MaxFPS         int
}

// Control reports whether the viewer may send input.
func (p Params) Control() bool { return p.Mode == "control" }

// AllowedParams are the only parameters a start_remote_session command may carry.
var AllowedParams = []string{"session_id", "token", "mode", "requester_name", "requester_email", "org_name",
	"reason", "consent_timeout_seconds", "idle_timeout_seconds", "max_duration_seconds", "max_fps"}

var (
	sessionIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)
	tokenRe     = regexp.MustCompile(`^[A-Za-z0-9_-]{32,64}$`)
)

func str(p map[string]any, k string, max int, required bool) (string, error) {
	raw, ok := p[k]
	if !ok || raw == nil {
		if required {
			return "", fmt.Errorf("%s is required", k)
		}
		return "", nil
	}
	s, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", k)
	}
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > max {
		return "", fmt.Errorf("%s is longer than %d characters", k, max)
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("%s must not contain control characters", k)
		}
	}
	if required && s == "" {
		return "", fmt.Errorf("%s is required", k)
	}
	return s, nil
}

func seconds(p map[string]any, k string, def, max time.Duration) (time.Duration, error) {
	raw, ok := p[k]
	if !ok || raw == nil {
		return def, nil
	}
	f, ok := raw.(float64)
	if !ok || f != math.Trunc(f) || f < 1 {
		return 0, fmt.Errorf("%s must be a positive integer", k)
	}
	d := time.Duration(f) * time.Second
	if d > max {
		d = max
	}
	return d, nil
}

// ParseParams validates the command parameters (the allowlist of keys is
// checked by commands.Validate). The token is required: it is minted by the
// server when the command is delivered.
func ParseParams(p map[string]any) (Params, error) {
	var out Params
	var err error
	if out.SessionID, err = str(p, "session_id", 32, true); err != nil {
		return out, err
	}
	if !sessionIDRe.MatchString(out.SessionID) {
		return out, errors.New("session_id must be 32 hex characters")
	}
	if out.Token, err = str(p, "token", 64, true); err != nil {
		return out, err
	}
	if !tokenRe.MatchString(out.Token) {
		return out, errors.New("token has an invalid format")
	}
	if out.Mode, err = str(p, "mode", 16, true); err != nil {
		return out, err
	}
	if out.Mode != "view" && out.Mode != "control" {
		return out, errors.New("mode must be view or control")
	}
	if out.RequesterName, err = str(p, "requester_name", 255, false); err != nil {
		return out, err
	}
	if out.RequesterEmail, err = str(p, "requester_email", 320, true); err != nil {
		return out, err
	}
	if out.OrgName, err = str(p, "org_name", 128, false); err != nil {
		return out, err
	}
	if out.Reason, err = str(p, "reason", 500, true); err != nil {
		return out, err
	}
	if out.ConsentTimeout, err = seconds(p, "consent_timeout_seconds", 60*time.Second, MaxConsentTimeout); err != nil {
		return out, err
	}
	if out.IdleTimeout, err = seconds(p, "idle_timeout_seconds", 15*time.Minute, MaxIdleTimeout); err != nil {
		return out, err
	}
	if out.MaxDuration, err = seconds(p, "max_duration_seconds", 2*time.Hour, MaxDuration); err != nil {
		return out, err
	}
	out.MaxFPS = 15
	if raw, ok := p["max_fps"]; ok && raw != nil {
		f, ok := raw.(float64)
		if !ok || f != math.Trunc(f) || f < 1 {
			return out, errors.New("max_fps must be a positive integer")
		}
		out.MaxFPS = min(int(f), MaxFPS)
	}
	return out, nil
}

// WireParams is what the helper gets (never the token).
func (p Params) WireParams() wire.Params {
	return wire.Params{SessionID: p.SessionID, Mode: p.Mode, RequesterName: p.RequesterName,
		RequesterEmail: p.RequesterEmail, OrgName: p.OrgName, Reason: p.Reason,
		ConsentSeconds: int(p.ConsentTimeout / time.Second), MaxFPS: p.MaxFPS}
}

// Event is one message from the helper: a JSON control message or a tile frame.
type Event struct {
	Kind byte // wire.KindJSON | wire.KindTile
	Data []byte
}

// Helper is the process in the user's session (consent prompt, indicator,
// capture, input). Events is closed when the helper exits.
type Helper interface {
	Events() <-chan Event
	Send(m wire.Msg) error
	// Close stops capture and input at once, removes the prompt and the
	// indicator and ends the process; it must leave no process behind.
	Close() error
}

// Platform is the OS backend.
type Platform interface {
	// Preflight: someone must be signed in and the screen unlocked.
	Preflight(ctx context.Context) error
	// Launch starts the helper in the user's session.
	Launch(ctx context.Context, p Params) (Helper, error)
	// Watch reports why the session must end (fast user switching, RDP
	// disconnect, the user locked the screen); nil when not supported.
	Watch(ctx context.Context) <-chan string
	// SendSAS sends Ctrl+Alt+Del (View and control only).
	SendSAS() error
}

// Conn is the WebSocket to the relay.
type Conn interface {
	Read(ctx context.Context) (binary bool, data []byte, err error)
	Write(ctx context.Context, binary bool, data []byte) error
	Close(code int, reason string) error
}

// DialFunc opens the relay socket for a session.
type DialFunc func(ctx context.Context, sessionID, token string) (Conn, error)

// Result of Start, reported as the command result.
type Result struct {
	Status    string // succeeded | failed
	Output    string
	ErrorCode string
}

// Controller runs at most one session at a time.
type Controller struct {
	Platform Platform
	Dial     DialFunc
	Now      func() time.Time
	// Tick is how often limits are checked (default 1 s; shorter in tests).
	Tick time.Duration
	// ConsentGrace: how much longer than the prompt the service waits for an
	// answer before it treats a silent helper as "no answer" (default 10 s).
	ConsentGrace time.Duration

	mu   sync.Mutex
	busy bool
	done chan struct{} // closed when the running session is over
}

// New builds a controller.
func New(p Platform, dial DialFunc) *Controller {
	return &Controller{Platform: p, Dial: dial, Now: time.Now, Tick: time.Second, ConsentGrace: consentGrace}
}

func failed(err error) Result {
	return Result{Status: "failed", Output: err.Error(), ErrorCode: CodeOf(err)}
}

// Start begins a session and returns once the relay socket is open and the
// helper runs (succeeded), or with the reason it could not start (failed).
// The session itself continues in the background until it ends; ctx is the
// agent's lifetime (cancelled when the service stops).
func (c *Controller) Start(ctx context.Context, p Params) Result {
	c.mu.Lock()
	if c.busy {
		c.mu.Unlock()
		return failed(Errorf(ErrBusy, "a remote session is already running on this device"))
	}
	c.busy = true
	done := make(chan struct{})
	c.done = done
	c.mu.Unlock()
	release := func() {
		c.mu.Lock()
		c.busy = false
		c.mu.Unlock()
		close(done)
	}
	if err := c.Platform.Preflight(ctx); err != nil {
		release()
		return failed(err)
	}
	conn, err := c.Dial(ctx, p.SessionID, p.Token)
	if err != nil {
		release()
		return failed(Errorf(ErrConnect, "connecting to the relay: %v", err))
	}
	h, err := c.Platform.Launch(ctx, p)
	if err != nil {
		code := CodeOf(err)
		c.write(ctx, conn, wire.Msg{T: "error", Code: code, Detail: err.Error()})
		_ = conn.Close(1000, "helper failed")
		release()
		return failed(err)
	}
	s := &session{c: c, p: p, conn: conn, helper: h, consentDeadline: c.Now().Add(p.ConsentTimeout + c.ConsentGrace)}
	go func() {
		defer release()
		s.run(ctx)
	}()
	return Result{Status: "succeeded", Output: fmt.Sprintf(
		"connected to the relay; consent prompt shown to the user (%s mode, answer within %s)", p.Mode, p.ConsentTimeout)}
}

// Wait blocks until the running session (if any) is over. Used by tests and shutdown.
func (c *Controller) Wait() {
	c.mu.Lock()
	done := c.done
	c.mu.Unlock()
	if done != nil {
		<-done
	}
}

// Busy reports whether a session is running.
func (c *Controller) Busy() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.busy
}

func (c *Controller) write(ctx context.Context, conn Conn, m wire.Msg) {
	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if ctx.Err() != nil { // the agent is stopping: still say goodbye
		wctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
	}
	_ = conn.Write(wctx, false, wire.Encode(m))
}

type serverMsg struct {
	binary bool
	data   []byte
}

type session struct {
	c      *Controller
	p      Params
	conn   Conn
	helper Helper

	consented       bool
	consentAt       time.Time
	consentDeadline time.Time
	lastActivity    time.Time
	stats           wire.Stats
	closed          bool
}

func (s *session) run(ctx context.Context) {
	log := slog.With("remote_session", s.p.SessionID, "mode", s.p.Mode)
	log.Info("remote session started; waiting for the user's consent")
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	fromServer := make(chan serverMsg, 64)
	go func() {
		defer close(fromServer)
		for {
			bin, data, err := s.conn.Read(rctx)
			if err != nil {
				return
			}
			select {
			case fromServer <- serverMsg{bin, data}:
			case <-rctx.Done():
				return
			}
		}
	}()
	watch := s.c.Platform.Watch(rctx)
	tick := time.NewTicker(s.c.Tick)
	defer tick.Stop()
	events := s.helper.Events()
	for !s.closed {
		select {
		case <-ctx.Done():
			s.end(ctx, "agent_stopping", true)
		case m, ok := <-fromServer:
			if !ok {
				// Server unreachable or the relay closed: stop locally right away.
				s.end(ctx, "server_unreachable", false)
				continue
			}
			s.fromServer(ctx, m)
		case ev, ok := <-events:
			if !ok {
				s.end(ctx, "helper_exit", true)
				continue
			}
			s.fromHelper(ctx, ev)
		case reason := <-watch:
			s.end(ctx, reason, true)
		case <-tick.C:
			s.limits(ctx)
		}
	}
	log.Info("remote session over", "frames", s.stats.Frames, "bytes", s.stats.Bytes,
		"input_injected", s.stats.InputInjected, "input_dropped", s.stats.InputDropped)
}

func (s *session) send(ctx context.Context, m wire.Msg) { s.c.write(ctx, s.conn, m) }

// end tears down: the helper first (capture and input stop at once), then the server.
func (s *session) end(ctx context.Context, reason string, notify bool) {
	if s.closed {
		return
	}
	s.closed = true
	if err := s.helper.Close(); err != nil {
		slog.Warn("closing the remote-session helper", "err", err)
	}
	if notify {
		st := s.stats
		s.send(ctx, wire.Msg{T: "stats", Stats: &st})
		s.send(ctx, wire.Msg{T: "ended", Reason: reason})
	}
	_ = s.conn.Close(1000, reason)
	slog.Info("remote session ended", "remote_session", s.p.SessionID, "reason", reason)
}

func (s *session) fromServer(ctx context.Context, m serverMsg) {
	if m.binary {
		return // nothing binary flows towards the device
	}
	msg, err := wire.Decode(m.data)
	if err != nil {
		return
	}
	now := s.c.Now()
	switch msg.T {
	case "end":
		s.end(ctx, "server:"+msg.Reason, false)
	case "input", "cad":
		if !s.p.Control() || !s.consented {
			// View only: dropped whatever the server or browser sends.
			s.stats.InputDropped++
			return
		}
		s.lastActivity = now
		if msg.T == "cad" {
			if err := s.c.Platform.SendSAS(); err != nil {
				slog.Warn("Ctrl+Alt+Del not sent", "err", err)
				s.send(ctx, wire.Msg{T: "error", Code: "ERR_SAS", Detail: err.Error()})
			}
			return
		}
		if s.helper.Send(msg) == nil {
			s.stats.InputInjected++
		}
	case "activity", "select_monitor":
		s.lastActivity = now
		if msg.T == "select_monitor" && s.consented {
			_ = s.helper.Send(msg)
		}
	case "ack", "quality":
		if s.consented {
			_ = s.helper.Send(msg)
		}
	}
}

func (s *session) fromHelper(ctx context.Context, ev Event) {
	if ev.Kind == wire.KindTile {
		if !s.consented {
			return // never a pixel before the user allowed it
		}
		wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := s.conn.Write(wctx, true, ev.Data)
		cancel()
		if err != nil {
			s.end(ctx, "server_unreachable", false)
			return
		}
		s.stats.Frames++
		s.stats.Bytes += len(ev.Data)
		return
	}
	msg, err := wire.Decode(ev.Data)
	if err != nil {
		return
	}
	switch msg.T {
	case "consent":
		if msg.Allow != nil && *msg.Allow && !s.consented {
			s.consented = true
			s.consentAt, s.lastActivity = s.c.Now(), s.c.Now()
			s.send(ctx, wire.Msg{T: "consent", Allow: wire.Bool(true)})
			return
		}
		reason := ""
		if msg.Reason == "timeout" {
			reason = "timeout"
		}
		s.send(ctx, wire.Msg{T: "consent", Allow: wire.Bool(false), Reason: reason})
		s.end(ctx, "denied", false)
	case "started", "monitors", "protected":
		if s.consented {
			s.send(ctx, fromHelperMsg(msg))
		}
	case "ended":
		// The user clicked End session (capture already stopped in the helper),
		// closed the indicator, or the helper lost its desktop for good.
		reason := msg.Reason
		if !helperEndReasons[reason] {
			reason = "helper_exit"
		}
		s.end(ctx, reason, true)
	case "error":
		code := msg.Code
		if !helperErrorCodes[code] {
			code = ErrHelper
		}
		s.send(ctx, wire.Msg{T: "error", Code: code, Detail: cleanDetail(msg.Detail)})
		s.end(ctx, "error", false)
	}
}

// The helper runs as the signed-in user, so what it reports is not trusted
// beyond these: only known end reasons and error codes reach the server, the
// detail text is cut short and stripped of control characters, and forwarded
// messages are rebuilt with the fields of their type only.
var (
	helperEndReasons = map[string]bool{"user_ended": true, "indicator_closed": true}
	helperErrorCodes = map[string]bool{ErrHelper: true}
)

const (
	maxHelperDetail   = 200
	maxHelperMonitors = 16
)

func cleanDetail(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == maxHelperDetail {
			break
		}
		if unicode.IsControl(r) || r == utf8.RuneError {
			r = ' '
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

func fromHelperMsg(m wire.Msg) wire.Msg {
	switch m.T {
	case "monitors":
		mons := m.Monitors
		if len(mons) > maxHelperMonitors {
			mons = mons[:maxHelperMonitors]
		}
		out := wire.Msg{T: "monitors", Monitors: mons}
		if m.Active != nil && *m.Active >= 0 && *m.Active < len(mons) {
			active := *m.Active
			out.Active = &active
		}
		return out
	case "protected":
		return wire.Msg{T: "protected", On: wire.Bool(m.On != nil && *m.On)}
	}
	return wire.Msg{T: m.T}
}

func (s *session) limits(ctx context.Context) {
	now := s.c.Now()
	if !s.consented {
		if now.After(s.consentDeadline) {
			s.send(ctx, wire.Msg{T: "consent", Allow: wire.Bool(false), Reason: "timeout"})
			s.end(ctx, "consent_timeout", false)
		}
		return
	}
	if now.Sub(s.consentAt) >= s.p.MaxDuration {
		s.end(ctx, "max_duration", true)
	} else if now.Sub(s.lastActivity) >= s.p.IdleTimeout {
		s.end(ctx, "idle", true)
	}
}

// MarshalParams is used by tests and the e2e fake.
func MarshalParams(p Params) map[string]any {
	b, _ := json.Marshal(map[string]any{
		"session_id": p.SessionID, "token": p.Token, "mode": p.Mode, "requester_name": p.RequesterName,
		"requester_email": p.RequesterEmail, "org_name": p.OrgName, "reason": p.Reason,
		"consent_timeout_seconds": int(p.ConsentTimeout / time.Second),
		"idle_timeout_seconds":    int(p.IdleTimeout / time.Second),
		"max_duration_seconds":    int(p.MaxDuration / time.Second), "max_fps": p.MaxFPS})
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}
