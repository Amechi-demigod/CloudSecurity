//go:build windows

package helper

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/remote/wire"
)

// The consent prompt and the indicator are plain Win32 windows painted by
// hand (no child controls), created with WS_EX_NOACTIVATE | WS_EX_TOPMOST |
// WS_EX_TOOLWINDOW: they never take keyboard focus, so keys the viewer injects
// (Alt+F4, Esc, Enter...) reach the foreground application, never them, and
// only the user's own clicks answer them (injected clicks on them are dropped
// in RunSession). The indicator re-asserts "topmost" every second; if it is
// closed, destroyed or hidden anyway the session ends - it is not re-created.
//
// Allow / Deny answer only a press and a release on the same button, both from
// a real pointing device (GetCurrentInputMessageSource: not SendInput, not a
// posted WM_LBUTTONUP from another process of the user), and not in the first
// second after the prompt appeared (clickguard.go). End session only needs a
// press and release on it: ending stays easy, also with assistive tools.

var (
	procRegisterClassExW   = user32.NewProc("RegisterClassExW")
	procCreateWindowExW    = user32.NewProc("CreateWindowExW")
	procDefWindowProcW     = user32.NewProc("DefWindowProcW")
	procDestroyWindow      = user32.NewProc("DestroyWindow")
	procGetMessageW        = user32.NewProc("GetMessageW")
	procTranslateMessage   = user32.NewProc("TranslateMessage")
	procDispatchMessageW   = user32.NewProc("DispatchMessageW")
	procPostThreadMessageW = user32.NewProc("PostThreadMessageW")
	procPostQuitMessage    = user32.NewProc("PostQuitMessage")
	procSetTimer           = user32.NewProc("SetTimer")
	procBeginPaint         = user32.NewProc("BeginPaint")
	procEndPaint           = user32.NewProc("EndPaint")
	procFillRect           = user32.NewProc("FillRect")
	procFrameRect          = user32.NewProc("FrameRect")
	procDrawTextW          = user32.NewProc("DrawTextW")
	procInvalidateRect     = user32.NewProc("InvalidateRect")
	procGetWindowRect      = user32.NewProc("GetWindowRect")
	procSetWindowPos       = user32.NewProc("SetWindowPos")
	procIsWindow           = user32.NewProc("IsWindow")
	procIsWindowVisible    = user32.NewProc("IsWindowVisible")
	procLoadCursorW        = user32.NewProc("LoadCursorW")
	procGetDpiForSystem    = user32.NewProc("GetDpiForSystem")
	procSystemParamsInfoW  = user32.NewProc("SystemParametersInfoW")
	procShowWindow         = user32.NewProc("ShowWindow")
	procGetInputSource     = user32.NewProc("GetCurrentInputMessageSource")

	gdi32                = windows.NewLazySystemDLL("gdi32.dll")
	procCreateSolidBrush = gdi32.NewProc("CreateSolidBrush")
	procCreateFontW      = gdi32.NewProc("CreateFontW")
	procSelectObject     = gdi32.NewProc("SelectObject")
	procSetBkMode        = gdi32.NewProc("SetBkMode")
	procSetTextColor     = gdi32.NewProc("SetTextColor")
	procDeleteObject     = gdi32.NewProc("DeleteObject")
)

const (
	wsPopup           = 0x80000000
	wsBorder          = 0x00800000
	wsExTopmost       = 0x00000008
	wsExToolWindow    = 0x00000080
	wsExNoActivate    = 0x08000000
	wmDestroy         = 0x0002
	wmClose           = 0x0010
	wmPaint           = 0x000F
	wmQueryEndSession = 0x0011
	wmEndSession      = 0x0016
	wmTimer           = 0x0113
	wmLButtonDown     = 0x0201
	wmLButtonUp       = 0x0202
	wmMouseActivate   = 0x0021
	wmApp             = 0x8000
	maNoActivate      = 3
	swShowNoActivate  = 4
	swpNoSize         = 0x0001
	swpNoMove         = 0x0002
	swpNoActivate     = 0x0010
	swpShowWindow     = 0x0040
	hwndTopmost       = ^uintptr(0) // (HWND)-1
	dtCenter          = 0x01
	dtVCenter         = 0x04
	dtSingleLine      = 0x20
	dtWordBreak       = 0x10
	dtEndEllipsis     = 0x8000
	transparent       = 1
	idcArrow          = 32512
	spiGetWorkArea    = 0x0030

	// INPUT_MESSAGE_SOURCE
	imdtMouse    = 0x02
	imdtTouch    = 0x04
	imdtPen      = 0x08
	imdtTouchpad = 0x10
	imoHardware  = 0x01

	consentSettle = time.Second

	msgConsent   = wmApp + 1
	msgIndicator = wmApp + 2
	msgDone      = wmApp + 3
)

type rect struct{ Left, Top, Right, Bottom int32 }

func (r rect) contains(x, y int32) bool {
	return x >= r.Left && x < r.Right && y >= r.Top && y < r.Bottom
}

type point struct{ X, Y int32 }

type msg struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
	Private uint32
}

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   windows.Handle
	Icon       windows.Handle
	Cursor     windows.Handle
	Background windows.Handle
	MenuName   *uint16
	ClassName  *uint16
	IconSm     windows.Handle
}

type paintStruct struct {
	Hdc        uintptr
	Erase      int32
	Paint      rect
	Restore    int32
	IncUpdate  int32
	RGBReserve [32]byte
}

func rgb(r, g, b byte) uintptr { return uintptr(r) | uintptr(g)<<8 | uintptr(b)<<16 }

type winUI struct {
	mu        sync.Mutex
	thread    uint32
	ready     chan error
	consent   uintptr
	indicator uintptr
	params    wire.Params
	deadline  time.Time
	answer    chan bool
	ended     chan string
	endOnce   sync.Once
	closed    bool
	scale     float64
	font      uintptr
	bold      uintptr
	// Button rectangles (client coordinates).
	allowBtn, denyBtn, endBtn rect
	// Press / release pairing (UI thread only).
	consentClick, endClick clickGuard
}

// The WndProc callback is process-wide; there is one UI per helper process.
var theUI *winUI

func newWinUI() (*winUI, error) {
	u := &winUI{ready: make(chan error, 1), answer: make(chan bool, 1), ended: make(chan string, 1),
		consentClick: clickGuard{strict: true, settle: consentSettle}}
	theUI = u
	go u.loop()
	if err := <-u.ready; err != nil {
		return nil, err
	}
	return u, nil
}

func utf16(s string) *uint16 {
	p, _ := windows.UTF16PtrFromString(s)
	return p
}

func (u *winUI) px(v int) int32 { return int32(float64(v)*u.scale + 0.5) }

func (u *winUI) loop() {
	runtime.LockOSThread()
	u.thread = windows.GetCurrentThreadId()
	u.scale = 1
	if r, _, _ := procGetDpiForSystem.Call(); r > 0 {
		u.scale = float64(r) / 96
	}
	inst := windows.Handle(0)
	cursor, _, _ := procLoadCursorW.Call(0, idcArrow)
	cb := windows.NewCallback(wndProc)
	for _, name := range []string{"CnappRemoteConsent", "CnappRemoteIndicator"} {
		wc := wndClassEx{WndProc: cb, Instance: inst, Cursor: windows.Handle(cursor), ClassName: utf16(name)}
		wc.Size = uint32(unsafe.Sizeof(wc))
		if r, _, err := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
			u.ready <- fmt.Errorf("RegisterClassEx: %v", err)
			return
		}
	}
	u.font, _, _ = procCreateFontW.Call(uintptr(-u.px(15)), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0,
		uintptr(unsafe.Pointer(utf16("Segoe UI"))))
	u.bold, _, _ = procCreateFontW.Call(uintptr(-u.px(17)), 0, 0, 0, 700, 0, 0, 0, 1, 0, 0, 5, 0,
		uintptr(unsafe.Pointer(utf16("Segoe UI"))))
	// Make sure the thread has a message queue before anyone posts to it.
	var m msg
	_, _, _ = procPostThreadMessageW.Call(uintptr(u.thread), 0, 0, 0)
	u.ready <- nil
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		if m.Hwnd == 0 {
			switch m.Message {
			case msgConsent:
				u.createConsent()
			case msgIndicator:
				u.createIndicator()
			case msgDone:
				u.destroy(&u.consent)
				u.destroy(&u.indicator)
				_, _, _ = procPostQuitMessage.Call(0)
			}
			continue
		}
		_, _, _ = procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		_, _, _ = procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
	_, _, _ = procDeleteObject.Call(u.font)
	_, _, _ = procDeleteObject.Call(u.bold)
}

func (u *winUI) destroy(h *uintptr) {
	u.mu.Lock()
	hwnd := *h
	*h = 0
	u.mu.Unlock()
	if hwnd != 0 {
		_, _, _ = procDestroyWindow.Call(hwnd)
	}
}

func workArea() rect {
	var r rect
	_, _, _ = procSystemParamsInfoW.Call(spiGetWorkArea, 0, uintptr(unsafe.Pointer(&r)), 0)
	return r
}

func (u *winUI) create(class string, x, y, w, h int32) uintptr {
	hwnd, _, _ := procCreateWindowExW.Call(wsExTopmost|wsExToolWindow|wsExNoActivate,
		uintptr(unsafe.Pointer(utf16(class))), uintptr(unsafe.Pointer(utf16("IT support"))),
		wsPopup|wsBorder, uintptr(x), uintptr(y), uintptr(w), uintptr(h), 0, 0, 0, 0)
	if hwnd != 0 {
		_, _, _ = procShowWindow.Call(hwnd, swShowNoActivate)
		_, _, _ = procSetTimer.Call(hwnd, 1, 1000, 0)
	}
	return hwnd
}

func (u *winUI) createConsent() {
	wa := workArea()
	w, h := u.px(480), u.px(300)
	x, y := wa.Left+(wa.Right-wa.Left-w)/2, wa.Top+(wa.Bottom-wa.Top-h)/2
	u.allowBtn = rect{w - u.px(220), h - u.px(56), w - u.px(124), h - u.px(20)}
	u.denyBtn = rect{w - u.px(112), h - u.px(56), w - u.px(16), h - u.px(20)}
	u.consentClick.show(time.Now())
	hwnd := u.create("CnappRemoteConsent", x, y, w, h)
	u.mu.Lock()
	u.consent = hwnd
	u.mu.Unlock()
	if hwnd == 0 {
		u.answerOnce(false)
	}
}

func (u *winUI) createIndicator() {
	wa := workArea()
	w, h := u.px(560), u.px(44)
	x, y := wa.Left+(wa.Right-wa.Left-w)/2, wa.Top+u.px(8)
	u.endBtn = rect{w - u.px(128), u.px(7), w - u.px(10), h - u.px(7)}
	u.endClick.show(time.Now())
	hwnd := u.create("CnappRemoteIndicator", x, y, w, h)
	u.mu.Lock()
	u.indicator = hwnd
	u.mu.Unlock()
	if hwnd == 0 {
		u.end("indicator_closed")
	}
}

func (u *winUI) answerOnce(allow bool) {
	select {
	case u.answer <- allow:
	default:
	}
}

func (u *winUI) end(reason string) {
	u.endOnce.Do(func() { u.ended <- reason })
}

func (u *winUI) post(m uint32) {
	_, _, _ = procPostThreadMessageW.Call(uintptr(u.thread), uintptr(m), 0, 0)
}

func modeLabel(mode string) (string, string) {
	if mode == "control" {
		return "View and control", "controlling"
	}
	return "View only", "viewing"
}

func requester(p wire.Params) string {
	if p.RequesterName != "" {
		return fmt.Sprintf("%s (%s)", p.RequesterName, p.RequesterEmail)
	}
	return p.RequesterEmail
}

func wndProc(hwnd, m, wp, lp uintptr) uintptr {
	u := theUI
	if u == nil {
		r, _, _ := procDefWindowProcW.Call(hwnd, m, wp, lp)
		return r
	}
	u.mu.Lock()
	isConsent, isIndicator := hwnd == u.consent && hwnd != 0, hwnd == u.indicator && hwnd != 0
	u.mu.Unlock()
	switch uint32(m) {
	case wmMouseActivate:
		return maNoActivate
	case wmPaint:
		u.paint(hwnd, isConsent)
		return 0
	case wmTimer:
		if isConsent {
			_, _, _ = procInvalidateRect.Call(hwnd, 0, 1)
		}
		if isIndicator {
			if r, _, _ := procIsWindowVisible.Call(hwnd); r == 0 {
				u.end("indicator_closed")
			}
			_, _, _ = procSetWindowPos.Call(hwnd, hwndTopmost, 0, 0, 0, 0,
				swpNoMove|swpNoSize|swpNoActivate|swpShowWindow)
		}
		return 0
	case wmLButtonDown, wmLButtonUp:
		x, y := int32(int16(lp&0xffff)), int32(int16(lp>>16&0xffff))
		hw, down := fromPointingDevice(), uint32(m) == wmLButtonDown
		switch {
		case isConsent:
			btn := ""
			if u.allowBtn.contains(x, y) {
				btn = "allow"
			} else if u.denyBtn.contains(x, y) {
				btn = "deny"
			}
			if down {
				u.consentClick.down(btn, hw, time.Now())
			} else if got := u.consentClick.up(btn, hw); got != "" {
				u.answerOnce(got == "allow")
			}
		case isIndicator:
			btn := ""
			if u.endBtn.contains(x, y) {
				btn = "end"
			}
			if down {
				u.endClick.down(btn, hw, time.Now())
			} else if u.endClick.up(btn, hw) == "end" {
				u.end("user_ended")
			}
		}
		return 0
	case wmClose, wmQueryEndSession, wmEndSession:
		// Closing either window by any means (Alt+F4 by the user, taskkill /im,
		// sign-out) ends the session or answers "deny".
		switch {
		case isIndicator:
			u.end("indicator_closed")
		case isConsent:
			u.answerOnce(false)
		case uint32(m) == wmClose:
			// A window this UI no longer tracks (the answered prompt): remove it.
			_, _, _ = procDestroyWindow.Call(hwnd)
		}
		if uint32(m) == wmQueryEndSession {
			return 1
		}
		return 0
	case wmDestroy:
		if isIndicator {
			u.end("indicator_closed")
		} else if isConsent {
			u.answerOnce(false)
		}
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, m, wp, lp)
	return r
}

// fromPointingDevice reports whether the message being processed came from a
// real mouse, touch screen, pen or touchpad (Windows 8+). Messages from
// SendInput, PostMessage or SendMessage do not.
func fromPointingDevice() bool {
	var src struct{ DeviceType, OriginID uint32 }
	if procGetInputSource.Find() != nil {
		return false
	}
	if r, _, _ := procGetInputSource.Call(uintptr(unsafe.Pointer(&src))); r == 0 {
		return false
	}
	switch src.DeviceType {
	case imdtMouse, imdtTouch, imdtPen, imdtTouchpad:
		return src.OriginID == imoHardware
	}
	return false
}

func (u *winUI) text(hdc uintptr, s string, r rect, flags uintptr, font uintptr, color uintptr) {
	_, _, _ = procSelectObject.Call(hdc, font)
	_, _, _ = procSetTextColor.Call(hdc, color)
	p, _ := windows.UTF16FromString(s)
	_, _, _ = procDrawTextW.Call(hdc, uintptr(unsafe.Pointer(&p[0])), uintptr(len(p)-1),
		uintptr(unsafe.Pointer(&r)), flags)
}

func (u *winUI) button(hdc uintptr, r rect, label string, bg uintptr) {
	br, _, _ := procCreateSolidBrush.Call(bg)
	_, _, _ = procFillRect.Call(hdc, uintptr(unsafe.Pointer(&r)), br)
	_, _, _ = procDeleteObject.Call(br)
	u.text(hdc, label, r, dtCenter|dtVCenter|dtSingleLine, u.bold, rgb(255, 255, 255))
}

func (u *winUI) paint(hwnd uintptr, consent bool) {
	var ps paintStruct
	hdc, _, _ := procBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
	defer func() { _, _, _ = procEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps))) }()
	var wr rect
	_, _, _ = procGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&wr)))
	client := rect{0, 0, wr.Right - wr.Left, wr.Bottom - wr.Top}
	_, _, _ = procSetBkMode.Call(hdc, transparent)
	u.mu.Lock()
	p, deadline := u.params, u.deadline
	u.mu.Unlock()
	modeName, verb := modeLabel(p.Mode)
	if !consent {
		bg, _, _ := procCreateSolidBrush.Call(rgb(176, 32, 32))
		_, _, _ = procFillRect.Call(hdc, uintptr(unsafe.Pointer(&client)), bg)
		_, _, _ = procDeleteObject.Call(bg)
		msgRect := rect{u.px(12), 0, u.endBtn.Left - u.px(8), client.Bottom}
		u.text(hdc, fmt.Sprintf("IT support (%s) is %s your screen", requester(p), verb), msgRect,
			dtVCenter|dtSingleLine|dtEndEllipsis, u.bold, rgb(255, 255, 255))
		u.button(hdc, u.endBtn, "End session", rgb(60, 60, 60))
		return
	}
	bg, _, _ := procCreateSolidBrush.Call(rgb(250, 250, 250))
	_, _, _ = procFillRect.Call(hdc, uintptr(unsafe.Pointer(&client)), bg)
	_, _, _ = procDeleteObject.Call(bg)
	frame, _, _ := procCreateSolidBrush.Call(rgb(120, 120, 120))
	_, _, _ = procFrameRect.Call(hdc, uintptr(unsafe.Pointer(&client)), frame)
	_, _, _ = procDeleteObject.Call(frame)
	pad := u.px(18)
	u.text(hdc, "IT support wants to see your screen", rect{pad, pad, client.Right - pad, pad + u.px(26)},
		dtSingleLine, u.bold, rgb(20, 20, 20))
	org := p.OrgName
	if org == "" {
		org = "your organisation"
	}
	body := fmt.Sprintf("%s from %s\nAccess: %s\nReason: %s\n\nNothing is shared until you click Allow. "+
		"You can end the session at any time with End session at the top of the screen.",
		requester(p), org, modeName, p.Reason)
	u.text(hdc, body, rect{pad, pad + u.px(34), client.Right - pad, u.allowBtn.Top - u.px(8)},
		dtWordBreak|dtEndEllipsis, u.font, rgb(40, 40, 40))
	left := int(time.Until(deadline).Seconds() + 0.5)
	if left < 0 {
		left = 0
	}
	u.text(hdc, fmt.Sprintf("Denied automatically in %d s", left),
		rect{pad, u.allowBtn.Top, u.allowBtn.Left - u.px(8), u.allowBtn.Bottom},
		dtVCenter|dtSingleLine, u.font, rgb(110, 110, 110))
	u.button(hdc, u.allowBtn, "Allow", rgb(16, 110, 190))
	u.button(hdc, u.denyBtn, "Deny", rgb(90, 90, 90))
}

// Consent shows the prompt until the user answers or ctx ends.
func (u *winUI) Consent(ctx context.Context, p wire.Params) bool {
	u.mu.Lock()
	u.params = p
	if d, ok := ctx.Deadline(); ok {
		u.deadline = d
	} else {
		u.deadline = time.Now().Add(60 * time.Second)
	}
	u.mu.Unlock()
	u.post(msgConsent)
	var allow bool
	select {
	case allow = <-u.answer:
	case <-ctx.Done():
		allow = false
	}
	u.destroyLater(&u.consent)
	return allow
}

func (u *winUI) destroyLater(h *uintptr) {
	u.mu.Lock()
	hwnd := *h
	*h = 0
	u.mu.Unlock()
	if hwnd != 0 {
		// DestroyWindow must run on the UI thread: closing it from here would
		// fail, so ask that thread (WM_CLOSE for a window that is no longer
		// tracked just destroys it).
		_, _, _ = procPostMessage(hwnd, wmClose)
	}
}

var procPostMessageW = user32.NewProc("PostMessageW")

func procPostMessage(hwnd uintptr, m uint32) (uintptr, uintptr, error) {
	return procPostMessageW.Call(hwnd, uintptr(m), 0, 0)
}

// ShowIndicator shows the always-on-top indicator.
func (u *winUI) ShowIndicator(p wire.Params) <-chan string {
	u.mu.Lock()
	u.params = p
	u.mu.Unlock()
	u.post(msgIndicator)
	return u.ended
}

// Excluded: (x, y) is on the prompt or the indicator.
func (u *winUI) Excluded(x, y int) bool {
	u.mu.Lock()
	hs := []uintptr{u.consent, u.indicator}
	u.mu.Unlock()
	for _, h := range hs {
		if h == 0 {
			continue
		}
		var r rect
		if ok, _, _ := procGetWindowRect.Call(h, uintptr(unsafe.Pointer(&r))); ok != 0 && r.contains(int32(x), int32(y)) {
			return true
		}
	}
	return false
}

// Close removes both windows and stops the UI thread.
func (u *winUI) Close() {
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return
	}
	u.closed = true
	u.mu.Unlock()
	u.post(msgDone)
}
