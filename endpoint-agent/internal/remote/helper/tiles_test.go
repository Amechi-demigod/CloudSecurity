package helper

import (
	"bytes"
	"image"
	"image/jpeg"
	"testing"
)

func solid(w, h int, v byte) *Frame {
	f := &Frame{W: w, H: h, Stride: w * 4, Pix: make([]byte, w*h*4)}
	for i := range f.Pix {
		f.Pix[i] = v
	}
	return f
}

func TestDiffFullFrameWithoutPrevious(t *testing.T) {
	got := Diff(nil, solid(100, 70, 1), 32)
	// 3 grid rows, each one run spanning the full width (last tiles clipped).
	want := []image.Rectangle{image.Rect(0, 0, 100, 32), image.Rect(0, 32, 100, 64), image.Rect(0, 64, 100, 70)}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestDiffOnlyChangedTilesMerged(t *testing.T) {
	prev, cur := solid(128, 64, 0), solid(128, 64, 0)
	if r := Diff(prev, cur, 32); len(r) != 0 {
		t.Fatalf("unchanged frame produced %v", r)
	}
	set := func(x, y int) { cur.Pix[y*cur.Stride+x*4] = 9 }
	set(40, 5) // tile (1,0)
	set(70, 5) // tile (2,0) - adjacent: merged
	set(5, 40) // tile (0,1)
	got := Diff(prev, cur, 32)
	want := []image.Rectangle{image.Rect(32, 0, 96, 32), image.Rect(0, 32, 32, 64)}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestEncodeJPEGSwapsBGRA(t *testing.T) {
	f := solid(16, 16, 0)
	for i := 0; i < len(f.Pix); i += 4 {
		f.Pix[i], f.Pix[i+1], f.Pix[i+2] = 255, 0, 0 // blue in BGRA
	}
	b, err := EncodeJPEG(f, image.Rect(0, 0, 16, 16), 90)
	if err != nil {
		t.Fatal(err)
	}
	img, err := jpeg.Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	r, g, bl, _ := img.At(8, 8).RGBA()
	if bl>>8 < 200 || r>>8 > 50 || g>>8 > 50 {
		t.Fatalf("expected blue, got r=%d g=%d b=%d", r>>8, g>>8, bl>>8)
	}
}

func TestKeymapCoversCommonShortcuts(t *testing.T) {
	for _, code := range []string{"ControlLeft", "AltLeft", "ShiftLeft", "MetaLeft", "Tab", "Escape", "Enter",
		"Backspace", "Delete", "ArrowLeft", "Home", "End", "PageUp", "F4", "F12", "KeyC", "KeyV", "KeyZ", "Digit1",
		"Space", "NumpadEnter", "ContextMenu", "PrintScreen"} {
		if _, ok := LookupKey(code); !ok {
			t.Errorf("%s not mapped", code)
		}
	}
	if k, _ := LookupKey("ArrowUp"); !k.Extended || k.Scan != 0x48 {
		t.Errorf("ArrowUp = %+v", k)
	}
	if k, _ := LookupKey("KeyA"); k.Extended || k.Scan != 0x1E {
		t.Errorf("KeyA = %+v", k)
	}
	if _, ok := LookupKey("Unidentified"); ok {
		t.Error("unknown code mapped")
	}
}
