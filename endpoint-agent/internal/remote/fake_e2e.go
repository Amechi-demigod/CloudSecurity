//go:build remote_fake

package remote

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"image/jpeg"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/remote/wire"
)

// DefaultPlatform in a `-tags remote_fake` build (scripts/agent_e2e.py only;
// scripts/agent_build_check.sh, run by CI and agent-release.yml on every
// release and installer binary, refuses a build with this tag): no helper process, no
// screen. The "user" allows at once, a synthetic 64x64 tile is sent four
// times a second and input is only counted. GitHub-hosted runners have no
// interactive session to capture. CNAPP_REMOTE_FAKE_END_AFTER=N makes the
// "user" click End session after N seconds.
func DefaultPlatform() Platform { return e2ePlatform{} }

type e2ePlatform struct{}

func (e2ePlatform) Preflight(context.Context) error { return nil }

func (e2ePlatform) Launch(ctx context.Context, p Params) (Helper, error) {
	h := &e2eHelper{events: make(chan Event, 16), stop: make(chan struct{})}
	go h.run(p)
	return h, nil
}

func (e2ePlatform) Watch(context.Context) <-chan string { return nil }
func (e2ePlatform) SendSAS() error                      { return nil }

type e2eHelper struct {
	events chan Event
	stop   chan struct{}
	once   sync.Once
	mu     sync.Mutex
	input  int
}

func e2eTile(seq uint32) []byte {
	img := image.NewRGBA(image.Rect(0, 0, 64, 64))
	for i := range img.Pix {
		img.Pix[i] = byte(seq*37 + uint32(i))
	}
	img.Set(0, 0, color.RGBA{255, 0, 0, 255})
	var b bytes.Buffer
	_ = jpeg.Encode(&b, img, &jpeg.Options{Quality: 60})
	return wire.AppendTile(nil, wire.Tile{W: 64, H: 64, Seq: seq, Flags: wire.TileFlagLast}, b.Bytes())
}

func (h *e2eHelper) emit(ev Event) bool {
	select {
	case h.events <- ev:
		return true
	case <-h.stop:
		return false
	}
}

func (h *e2eHelper) run(p Params) {
	defer close(h.events)
	select {
	case <-time.After(200 * time.Millisecond):
	case <-h.stop:
		return
	}
	if !h.emit(Event{wire.KindJSON, wire.Encode(wire.Msg{T: "consent", Allow: wire.Bool(true)})}) {
		return
	}
	zero := 0
	h.emit(Event{wire.KindJSON, wire.Encode(wire.Msg{T: "monitors", Active: &zero,
		Monitors: []wire.Monitor{{ID: 0, W: 1280, H: 720, Scale: 1, Primary: true}}})})
	h.emit(Event{wire.KindJSON, wire.Encode(wire.Msg{T: "started"})})
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	var userEnds <-chan time.Time
	if n, err := strconv.Atoi(os.Getenv("CNAPP_REMOTE_FAKE_END_AFTER")); err == nil && n > 0 {
		userEnds = time.After(time.Duration(n) * time.Second)
	}
	for seq := uint32(1); ; seq++ {
		select {
		case <-h.stop:
			return
		case <-userEnds:
			h.emit(Event{wire.KindJSON, wire.Encode(wire.Msg{T: "ended", Reason: "user_ended"})})
			return
		case <-t.C:
			if !h.emit(Event{wire.KindTile, e2eTile(seq)}) {
				return
			}
		}
	}
}

func (h *e2eHelper) Events() <-chan Event { return h.events }

func (h *e2eHelper) Send(m wire.Msg) error {
	if m.T == "input" {
		h.mu.Lock()
		h.input++
		h.mu.Unlock()
	}
	return nil
}

func (h *e2eHelper) Close() error {
	h.once.Do(func() {
		close(h.stop)
		h.mu.Lock()
		slog.Info("fake remote-session helper closed", "input_events", h.input)
		h.mu.Unlock()
	})
	return nil
}
