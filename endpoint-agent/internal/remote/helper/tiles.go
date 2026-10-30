package helper

import (
	"bytes"
	"image"
	"image/jpeg"
)

// Frame is a captured monitor image: 32-bit BGRA rows (Windows' native layout).
type Frame struct {
	W, H   int
	Stride int
	Pix    []byte
}

// Diff returns the rectangles of `cur` that differ from `prev`, on a grid of
// tile x tile pixels, with changed tiles of one grid row merged into runs.
// Everything is "changed" when there is no previous frame of the same size.
func Diff(prev, cur *Frame, tile int) []image.Rectangle {
	if cur == nil || cur.W <= 0 || cur.H <= 0 {
		return nil
	}
	full := prev == nil || prev.W != cur.W || prev.H != cur.H
	var out []image.Rectangle
	for ty := 0; ty < cur.H; ty += tile {
		y1 := min(ty+tile, cur.H)
		runStart := -1
		for tx := 0; tx < cur.W; tx += tile {
			changed := full || tileChanged(prev, cur, tx, ty, min(tx+tile, cur.W), y1)
			switch {
			case changed && runStart < 0:
				runStart = tx
			case !changed && runStart >= 0:
				out = append(out, image.Rect(runStart, ty, tx, y1))
				runStart = -1
			}
		}
		if runStart >= 0 {
			out = append(out, image.Rect(runStart, ty, cur.W, y1))
		}
	}
	return out
}

func tileChanged(prev, cur *Frame, x0, y0, x1, y1 int) bool {
	for y := y0; y < y1; y++ {
		a := prev.Pix[y*prev.Stride+x0*4 : y*prev.Stride+x1*4]
		b := cur.Pix[y*cur.Stride+x0*4 : y*cur.Stride+x1*4]
		if !bytes.Equal(a, b) {
			return true
		}
	}
	return false
}

// EncodeJPEG encodes rectangle r of f.
func EncodeJPEG(f *Frame, r image.Rectangle, quality int) ([]byte, error) {
	img := image.NewRGBA(image.Rect(0, 0, r.Dx(), r.Dy()))
	for y := 0; y < r.Dy(); y++ {
		src := f.Pix[(r.Min.Y+y)*f.Stride+r.Min.X*4:]
		dst := img.Pix[y*img.Stride:]
		for x := 0; x < r.Dx(); x++ {
			dst[x*4], dst[x*4+1], dst[x*4+2], dst[x*4+3] = src[x*4+2], src[x*4+1], src[x*4], 255
		}
	}
	var b bytes.Buffer
	b.Grow(r.Dx() * r.Dy() / 4)
	if err := jpeg.Encode(&b, img, &jpeg.Options{Quality: quality}); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
