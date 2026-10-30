// Package wire is the framing between the agent service and its remote-session
// helper process (a named pipe pair on Windows), and the message types both
// sides and the server relay share.
//
// A frame is a 1-byte kind, a 4-byte big-endian length and the payload: a JSON
// control message (KindJSON) or a screen tile (KindTile: TileHeaderSize bytes
// of header, then JPEG). Tiles go to the server unchanged.
package wire

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Frame kinds.
const (
	KindJSON byte = 1
	KindTile byte = 2
)

// MaxFrame bounds one frame (a JPEG tile of a 4K monitor fits easily).
const MaxFrame = 2 << 20

// TileHeaderSize is the tile header: u8 kind (1), u8 monitor, u16 x, u16 y,
// u16 w, u16 h, u32 frame seq, u16 flags (bit 0: last tile of the frame).
const TileHeaderSize = 16

// TileFlagLast marks the last tile of a frame (the viewer acks it).
const TileFlagLast = 1

// Tile is a decoded tile header.
type Tile struct {
	Monitor    uint8
	X, Y, W, H uint16
	Seq        uint32
	Flags      uint16
}

// AppendTile appends the header for t and the JPEG bytes to dst.
func AppendTile(dst []byte, t Tile, jpeg []byte) []byte {
	var h [TileHeaderSize]byte
	h[0] = 1
	h[1] = t.Monitor
	binary.BigEndian.PutUint16(h[2:], t.X)
	binary.BigEndian.PutUint16(h[4:], t.Y)
	binary.BigEndian.PutUint16(h[6:], t.W)
	binary.BigEndian.PutUint16(h[8:], t.H)
	binary.BigEndian.PutUint32(h[10:], t.Seq)
	binary.BigEndian.PutUint16(h[14:], t.Flags)
	return append(append(dst, h[:]...), jpeg...)
}

// ParseTile decodes a tile header.
func ParseTile(b []byte) (Tile, []byte, error) {
	if len(b) < TileHeaderSize || b[0] != 1 {
		return Tile{}, nil, errors.New("not a tile")
	}
	return Tile{Monitor: b[1], X: binary.BigEndian.Uint16(b[2:]), Y: binary.BigEndian.Uint16(b[4:]),
		W: binary.BigEndian.Uint16(b[6:]), H: binary.BigEndian.Uint16(b[8:]), Seq: binary.BigEndian.Uint32(b[10:]),
		Flags: binary.BigEndian.Uint16(b[14:])}, b[TileHeaderSize:], nil
}

// Msg is a JSON control message. T is the type; the other fields are used by
// some types only (see internal/remote for the protocol).
type Msg struct {
	T string `json:"t"`

	// consent
	Allow  *bool  `json:"allow,omitempty"`
	Reason string `json:"reason,omitempty"`
	// error: the error code; input (kind key): the browser's KeyboardEvent.code
	Code   string `json:"code,omitempty"`
	Detail string `json:"detail,omitempty"`
	// protected
	On *bool `json:"on,omitempty"`
	// input: kind move | button | wheel | key; x, y in [0,1] of the active monitor
	Kind   string   `json:"kind,omitempty"`
	X      *float64 `json:"x,omitempty"`
	Y      *float64 `json:"y,omitempty"`
	Button *int     `json:"button,omitempty"`
	Down   *bool    `json:"down,omitempty"`
	DX     *float64 `json:"dx,omitempty"`
	DY     *float64 `json:"dy,omitempty"`
	// ack
	Seq *uint32 `json:"seq,omitempty"`
	// select_monitor
	ID *int `json:"id,omitempty"`
	// quality: low | auto | high
	Level string `json:"level,omitempty"`
	// monitors
	Monitors []Monitor `json:"monitors,omitempty"`
	Active   *int      `json:"active,omitempty"`
	// stats
	Stats *Stats `json:"stats,omitempty"`
	// params (service -> helper only)
	Params *Params `json:"params,omitempty"`
}

// Monitor describes one display (physical pixels; the helper is per-monitor DPI aware).
type Monitor struct {
	ID      int     `json:"id"`
	X       int     `json:"x"`
	Y       int     `json:"y"`
	W       int     `json:"w"`
	H       int     `json:"h"`
	Scale   float64 `json:"scale"`
	Primary bool    `json:"primary"`
}

// Stats are counters only: never content.
type Stats struct {
	Frames        int `json:"frames"`
	Bytes         int `json:"bytes"`
	InputInjected int `json:"input_injected"`
	InputDropped  int `json:"input_dropped"`
}

// Params is what the helper needs to show the consent prompt and run.
type Params struct {
	SessionID      string `json:"session_id"`
	Mode           string `json:"mode"`
	RequesterName  string `json:"requester_name"`
	RequesterEmail string `json:"requester_email"`
	OrgName        string `json:"org_name"`
	Reason         string `json:"reason"`
	ConsentSeconds int    `json:"consent_seconds"`
	MaxFPS         int    `json:"max_fps"`
}

// Encode marshals a message.
func Encode(m Msg) []byte {
	b, _ := json.Marshal(m)
	return b
}

// Decode parses a message; it must have a type.
func Decode(b []byte) (Msg, error) {
	var m Msg
	if err := json.Unmarshal(b, &m); err != nil {
		return Msg{}, err
	}
	if m.T == "" {
		return Msg{}, errors.New("message without a type")
	}
	return m, nil
}

// Bool is a helper for optional fields.
func Bool(v bool) *bool { return &v }

// Writer writes frames; safe for concurrent use.
type Writer struct {
	mu sync.Mutex
	w  io.Writer
}

// NewWriter wraps w.
func NewWriter(w io.Writer) *Writer { return &Writer{w: w} }

// Write sends one frame.
func (w *Writer) Write(kind byte, payload []byte) error {
	if len(payload) > MaxFrame {
		return fmt.Errorf("frame of %d bytes exceeds %d", len(payload), MaxFrame)
	}
	var h [5]byte
	h[0] = kind
	binary.BigEndian.PutUint32(h[1:], uint32(len(payload)))
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := w.w.Write(h[:]); err != nil {
		return err
	}
	_, err := w.w.Write(payload)
	return err
}

// WriteMsg sends a JSON control message.
func (w *Writer) WriteMsg(m Msg) error { return w.Write(KindJSON, Encode(m)) }

// ReadFrame reads one frame.
func ReadFrame(r io.Reader) (byte, []byte, error) {
	var h [5]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(h[1:])
	if n > MaxFrame {
		return 0, nil, fmt.Errorf("frame of %d bytes exceeds %d", n, MaxFrame)
	}
	if h[0] != KindJSON && h[0] != KindTile {
		return 0, nil, fmt.Errorf("unknown frame kind %d", h[0])
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return h[0], buf, nil
}
