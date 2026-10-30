package wire

import (
	"bytes"
	"strings"
	"testing"
)

func TestFramesRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	if err := w.WriteMsg(Msg{T: "consent", Allow: Bool(true)}); err != nil {
		t.Fatal(err)
	}
	tile := AppendTile(nil, Tile{Monitor: 1, X: 64, Y: 128, W: 32, H: 16, Seq: 7, Flags: TileFlagLast}, []byte("jpg"))
	if err := w.Write(KindTile, tile); err != nil {
		t.Fatal(err)
	}
	kind, data, err := ReadFrame(&buf)
	if err != nil || kind != KindJSON {
		t.Fatalf("%d %v", kind, err)
	}
	m, err := Decode(data)
	if err != nil || m.T != "consent" || !*m.Allow {
		t.Fatalf("%+v %v", m, err)
	}
	kind, data, err = ReadFrame(&buf)
	if err != nil || kind != KindTile {
		t.Fatalf("%d %v", kind, err)
	}
	hdr, jpg, err := ParseTile(data)
	if err != nil || hdr != (Tile{Monitor: 1, X: 64, Y: 128, W: 32, H: 16, Seq: 7, Flags: TileFlagLast}) ||
		string(jpg) != "jpg" || len(tile) != TileHeaderSize+3 {
		t.Fatalf("%+v %q %v", hdr, jpg, err)
	}
}

func TestOversizedAndUnknownFramesRejected(t *testing.T) {
	if err := NewWriter(&bytes.Buffer{}).Write(KindTile, make([]byte, MaxFrame+1)); err == nil {
		t.Fatal("oversized frame written")
	}
	bad := []byte{KindJSON, 0xff, 0xff, 0xff, 0xff}
	if _, _, err := ReadFrame(bytes.NewReader(bad)); err == nil {
		t.Fatal("oversized frame read")
	}
	if _, _, err := ReadFrame(bytes.NewReader([]byte{9, 0, 0, 0, 0})); err == nil {
		t.Fatal("unknown kind accepted")
	}
	if _, err := Decode([]byte(`{"x":1}`)); err == nil {
		t.Fatal("message without a type accepted")
	}
}

func TestInputCodeIsTheKeyboardEventCode(t *testing.T) {
	m, err := Decode([]byte(`{"t":"input","kind":"key","code":"KeyA","down":true}`))
	if err != nil || m.Code != "KeyA" || !*m.Down {
		t.Fatalf("%+v %v", m, err)
	}
	if !strings.Contains(string(Encode(m)), `"code":"KeyA"`) {
		t.Fatal("code not encoded")
	}
}
