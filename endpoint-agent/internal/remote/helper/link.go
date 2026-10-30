package helper

import (
	"io"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/remote/wire"
)

// StreamLink is a Link over the pipe pair to the service.
type StreamLink struct {
	w    *wire.Writer
	recv chan wire.Msg
}

// NewStreamLink reads control messages from r (until it fails) and writes to w.
func NewStreamLink(r io.Reader, w io.Writer) *StreamLink {
	l := &StreamLink{w: wire.NewWriter(w), recv: make(chan wire.Msg, 64)}
	go func() {
		defer close(l.recv)
		for {
			kind, data, err := wire.ReadFrame(r)
			if err != nil {
				return
			}
			if kind != wire.KindJSON {
				continue
			}
			if m, err := wire.Decode(data); err == nil {
				l.recv <- m
			}
		}
	}()
	return l
}

func (l *StreamLink) Recv() <-chan wire.Msg   { return l.recv }
func (l *StreamLink) Send(m wire.Msg) error   { return l.w.WriteMsg(m) }
func (l *StreamLink) SendTile(b []byte) error { return l.w.Write(wire.KindTile, b) }
