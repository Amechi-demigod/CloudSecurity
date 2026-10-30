//go:build windows

package helper

import (
	"errors"
	"fmt"
	"math"
	"unsafe"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/remote/wire"
)

// Input runs at the user's own privilege (medium integrity): Windows UIPI
// blocks it from elevated "Run as administrator" windows, which can be seen
// but not clicked or typed into (docs/DEVICE_MANAGEMENT.md, Limitations).

var (
	procSendInput        = user32.NewProc("SendInput")
	procGetSystemMetrics = user32.NewProc("GetSystemMetrics")
)

const (
	inputMouseType    = 0
	inputKeyboardType = 1

	mouseMove       = 0x0001
	mouseLeftDown   = 0x0002
	mouseLeftUp     = 0x0004
	mouseRightDown  = 0x0008
	mouseRightUp    = 0x0010
	mouseMiddleDown = 0x0020
	mouseMiddleUp   = 0x0040
	mouseWheel      = 0x0800
	mouseHWheel     = 0x1000
	mouseVirtual    = 0x4000
	mouseAbsolute   = 0x8000
	wheelDelta      = 120

	keyExtended = 0x0001
	keyUp       = 0x0002
	keyScanCode = 0x0008

	smXVirtual  = 76
	smYVirtual  = 77
	smCXVirtual = 78
	smCYVirtual = 79
)

type mouseInput struct {
	Dx, Dy    int32
	MouseData uint32
	Flags     uint32
	Time      uint32
	ExtraInfo uintptr
}

type keybdInput struct {
	Vk, Scan  uint16
	Flags     uint32
	Time      uint32
	ExtraInfo uintptr
}

// INPUT is a tagged union; these two views have the same size (checked in init).
type inputMouse struct {
	Type uint32
	Mi   mouseInput
}

type inputKey struct {
	Type uint32
	Ki   keybdInput
	_    [unsafe.Sizeof(mouseInput{}) - unsafe.Sizeof(keybdInput{})]byte
}

func init() {
	if unsafe.Sizeof(inputMouse{}) != unsafe.Sizeof(inputKey{}) {
		panic("INPUT layout mismatch")
	}
}

type winInjector struct{}

func newInjector() *winInjector { return &winInjector{} }

func metric(i uintptr) int32 {
	r, _, _ := procGetSystemMetrics.Call(i)
	return int32(r)
}

func sendMouse(mi mouseInput) error {
	in := inputMouse{Type: inputMouseType, Mi: mi}
	if r, _, err := procSendInput.Call(1, uintptr(unsafe.Pointer(&in)), unsafe.Sizeof(in)); r != 1 {
		return fmt.Errorf("SendInput: %v (the desktop may be a protected prompt)", err)
	}
	return nil
}

func sendKey(ki keybdInput) error {
	in := inputKey{Type: inputKeyboardType, Ki: ki}
	if r, _, err := procSendInput.Call(1, uintptr(unsafe.Pointer(&in)), unsafe.Sizeof(in)); r != 1 {
		return fmt.Errorf("SendInput: %v (the desktop may be a protected prompt)", err)
	}
	return nil
}

// absolute converts virtual-desktop pixels to SendInput's 0..65535 range.
func absolute(x, y int) (int32, int32) {
	vx, vy, vw, vh := metric(smXVirtual), metric(smYVirtual), metric(smCXVirtual), metric(smCYVirtual)
	if vw < 2 || vh < 2 {
		return 0, 0
	}
	ax := (int64(int32(x)-vx)*65535 + int64(vw-1)/2) / int64(vw-1)
	ay := (int64(int32(y)-vy)*65535 + int64(vh-1)/2) / int64(vh-1)
	return int32(ax), int32(ay)
}

func (w *winInjector) move(x, y int) error {
	ax, ay := absolute(x, y)
	return sendMouse(mouseInput{Dx: ax, Dy: ay, Flags: mouseMove | mouseAbsolute | mouseVirtual})
}

func notches(v *float64) uint32 {
	if v == nil || math.IsNaN(*v) {
		return 0
	}
	n := math.Max(-10, math.Min(10, *v))
	return uint32(int32(math.Round(-n * wheelDelta)))
}

// Inject replays one viewer input message.
func (w *winInjector) Inject(m wire.Msg, x, y int, ok bool) error {
	switch m.Kind {
	case "move":
		if !ok {
			return errors.New("move without a position")
		}
		return w.move(x, y)
	case "button":
		if m.Button == nil || m.Down == nil {
			return errors.New("button needs button and down")
		}
		if ok {
			if err := w.move(x, y); err != nil {
				return err
			}
		}
		flags := map[[2]int]uint32{{0, 1}: mouseLeftDown, {0, 0}: mouseLeftUp, {1, 1}: mouseMiddleDown,
			{1, 0}: mouseMiddleUp, {2, 1}: mouseRightDown, {2, 0}: mouseRightUp}
		down := 0
		if *m.Down {
			down = 1
		}
		f, known := flags[[2]int{*m.Button, down}]
		if !known {
			return fmt.Errorf("unknown mouse button %d", *m.Button)
		}
		return sendMouse(mouseInput{Flags: f})
	case "wheel":
		if d := notches(m.DY); d != 0 {
			if err := sendMouse(mouseInput{Flags: mouseWheel, MouseData: d}); err != nil {
				return err
			}
		}
		if d := notches(m.DX); d != 0 {
			// Horizontal: positive is right for both the browser and Windows.
			return sendMouse(mouseInput{Flags: mouseHWheel, MouseData: uint32(-int32(d))})
		}
		return nil
	case "key":
		k, known := LookupKey(m.Code)
		if !known || m.Down == nil {
			return fmt.Errorf("unmapped key %q", m.Code)
		}
		f := uint32(keyScanCode)
		if k.Extended {
			f |= keyExtended
		}
		if !*m.Down {
			f |= keyUp
		}
		return sendKey(keybdInput{Scan: k.Scan, Flags: f})
	}
	return fmt.Errorf("unknown input kind %q", m.Kind)
}
