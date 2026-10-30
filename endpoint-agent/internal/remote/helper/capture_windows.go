//go:build windows

package helper

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/remote/wire"
)

// Capture uses DXGI Desktop Duplication (IDXGIOutputDuplication) per monitor,
// with a GDI BitBlt fallback for outputs it cannot duplicate (another GPU,
// basic display adapters in some VMs). When the input desktop is not the
// user's - the UAC secure desktop, the sign-in screen - nothing is captured
// and Grab reports `protected` (the viewer shows "the user's screen is on a
// protected prompt"); v1 does not capture secure desktops.

var (
	d3d11                     = windows.NewLazySystemDLL("d3d11.dll")
	procD3D11CreateDevice     = d3d11.NewProc("D3D11CreateDevice")
	shcore                    = windows.NewLazySystemDLL("shcore.dll")
	procGetDpiForMonitor      = shcore.NewProc("GetDpiForMonitor")
	procEnumDisplayMonitors   = user32.NewProc("EnumDisplayMonitors")
	procGetMonitorInfoW       = user32.NewProc("GetMonitorInfoW")
	procOpenInputDesktop      = user32.NewProc("OpenInputDesktop")
	procCloseDesktop          = user32.NewProc("CloseDesktop")
	procGetUserObjectInfoW    = user32.NewProc("GetUserObjectInformationW")
	procGetDC                 = user32.NewProc("GetDC")
	procReleaseDC             = user32.NewProc("ReleaseDC")
	procCreateCompatibleDC    = gdi32.NewProc("CreateCompatibleDC")
	procDeleteDC              = gdi32.NewProc("DeleteDC")
	procCreateDIBSection      = gdi32.NewProc("CreateDIBSection")
	procBitBlt                = gdi32.NewProc("BitBlt")
	enumMonitorsCallback      = windows.NewCallback(enumMonitorProc)
	enumMonitorsTarget        *[]monitorEntry
	iidIDXGIDevice            = windows.GUID{Data1: 0x54ec77fa, Data2: 0x1377, Data3: 0x44e6, Data4: [8]byte{0x8c, 0x32, 0x88, 0xfd, 0x5f, 0x44, 0xc8, 0x4c}}
	iidIDXGIOutput1           = windows.GUID{Data1: 0x00cddea8, Data2: 0x939b, Data3: 0x4b83, Data4: [8]byte{0xa3, 0x40, 0xa6, 0x85, 0x22, 0x66, 0x66, 0xcc}}
	iidID3D11Texture2D        = windows.GUID{Data1: 0x6f15aaf2, Data2: 0xd208, Data3: 0x4e89, Data4: [8]byte{0x9a, 0xb4, 0x48, 0x95, 0x35, 0xd3, 0x4f, 0x9c}}
	errDuplicationUnavailable = errors.New("desktop duplication unavailable for this output")
)

const (
	dxgiErrorNotFound    = 0x887A0002
	dxgiErrorAccessLost  = 0x887A0026
	dxgiErrorWaitTimeout = 0x887A0027
	d3dDriverHardware    = 1
	d3d11CreateBGRA      = 0x20
	d3d11SDKVersion      = 7
	d3d11UsageStaging    = 3
	d3d11CPUAccessRead   = 0x20000
	d3d11MapRead         = 1
	srcCopy              = 0x00CC0020
	captureBlt           = 0x40000000
	monitorInfoPrimary   = 1
	uoiName              = 2
	desktopReadObjects   = 0x0001
)

// comObj is a COM interface pointer: its first word points to the vtable.
type comObj struct{ vtbl *[64]uintptr }

func (o *comObj) call(i int, args ...uintptr) uintptr {
	r, _, _ := syscall.SyscallN(o.vtbl[i], append([]uintptr{uintptr(unsafe.Pointer(o))}, args...)...)
	return r
}

func (o *comObj) release() {
	if o != nil {
		o.call(2)
	}
}

func (o *comObj) query(iid *windows.GUID) (*comObj, error) {
	var out *comObj
	if hr := o.call(0, uintptr(unsafe.Pointer(iid)), uintptr(unsafe.Pointer(&out))); int32(hr) < 0 || out == nil {
		return nil, fmt.Errorf("QueryInterface: 0x%08x", uint32(hr))
	}
	return out, nil
}

type texture2DDesc struct {
	Width, Height, MipLevels, ArraySize uint32
	Format                              uint32
	SampleCount, SampleQuality          uint32
	Usage, BindFlags, CPUAccessFlags    uint32
	MiscFlags                           uint32
}

type mappedSubresource struct {
	Data       *byte
	RowPitch   uint32
	DepthPitch uint32
}

type outduplFrameInfo struct {
	LastPresentTime           int64
	LastMouseUpdateTime       int64
	AccumulatedFrames         uint32
	RectsCoalesced            int32
	ProtectedContentMaskedOut int32
	PointerX, PointerY        int32
	PointerVisible            int32
	TotalMetadataBufferSize   uint32
	PointerShapeBufferSize    uint32
}

type dxgiOutputDesc struct {
	DeviceName        [32]uint16
	DesktopCoords     rect
	AttachedToDesktop int32
	Rotation          uint32
	Monitor           uintptr
}

type monitorInfoEx struct {
	Size    uint32
	Monitor rect
	Work    rect
	Flags   uint32
	Device  [32]uint16
}

type monitorEntry struct {
	handle uintptr
	mon    wire.Monitor
}

func enumMonitorProc(hmon, hdc, lprc, data uintptr) uintptr {
	if enumMonitorsTarget == nil {
		return 0
	}
	mi := monitorInfoEx{}
	mi.Size = uint32(unsafe.Sizeof(mi))
	if r, _, _ := procGetMonitorInfoW.Call(hmon, uintptr(unsafe.Pointer(&mi))); r == 0 {
		return 1
	}
	scale := 1.0
	var dx, dy uint32
	if procGetDpiForMonitor.Find() == nil {
		if hr, _, _ := procGetDpiForMonitor.Call(hmon, 0, uintptr(unsafe.Pointer(&dx)),
			uintptr(unsafe.Pointer(&dy))); int32(hr) >= 0 && dx > 0 {
			scale = float64(dx) / 96
		}
	}
	m := wire.Monitor{ID: len(*enumMonitorsTarget), X: int(mi.Monitor.Left), Y: int(mi.Monitor.Top),
		W: int(mi.Monitor.Right - mi.Monitor.Left), H: int(mi.Monitor.Bottom - mi.Monitor.Top),
		Scale: scale, Primary: mi.Flags&monitorInfoPrimary != 0}
	*enumMonitorsTarget = append(*enumMonitorsTarget, monitorEntry{handle: hmon, mon: m})
	return 1
}

type duplication struct {
	dup     *comObj
	staging *comObj
	desc    texture2DDesc
	last    *Frame
}

type winCapturer struct {
	device, context *comObj
	monitors        []monitorEntry
	dups            map[int]*duplication
	noDXGI          bool
}

func newCapturer() *winCapturer { return &winCapturer{dups: map[int]*duplication{}} }

// Monitors lists the displays (physical pixels).
func (c *winCapturer) Monitors() ([]wire.Monitor, error) {
	var entries []monitorEntry
	enumMonitorsTarget = &entries
	r, _, err := procEnumDisplayMonitors.Call(0, 0, enumMonitorsCallback, 0)
	enumMonitorsTarget = nil
	if r == 0 {
		return nil, fmt.Errorf("EnumDisplayMonitors: %v", err)
	}
	c.monitors = entries
	out := make([]wire.Monitor, len(entries))
	for i, e := range entries {
		out[i] = e.mon
	}
	return out, nil
}

// protectedDesktop: the input desktop is not the user's "Default" desktop.
func protectedDesktop() bool {
	h, _, _ := procOpenInputDesktop.Call(0, 0, desktopReadObjects)
	if h == 0 {
		return true // a user process cannot open Winlogon's secure desktop
	}
	defer func() { _, _, _ = procCloseDesktop.Call(h) }()
	var name [64]uint16
	var n uint32
	if r, _, _ := procGetUserObjectInfoW.Call(h, uoiName, uintptr(unsafe.Pointer(&name[0])),
		uintptr(len(name)*2), uintptr(unsafe.Pointer(&n))); r == 0 {
		return true
	}
	return windows.UTF16ToString(name[:]) != "Default"
}

func (c *winCapturer) ensureDevice() error {
	if c.device != nil {
		return nil
	}
	if c.noDXGI {
		return errDuplicationUnavailable
	}
	if procD3D11CreateDevice.Find() != nil {
		c.noDXGI = true
		return errDuplicationUnavailable
	}
	var dev, ctx *comObj
	var level uint32
	hr, _, _ := procD3D11CreateDevice.Call(0, d3dDriverHardware, 0, d3d11CreateBGRA, 0, 0, d3d11SDKVersion,
		uintptr(unsafe.Pointer(&dev)), uintptr(unsafe.Pointer(&level)), uintptr(unsafe.Pointer(&ctx)))
	if int32(hr) < 0 || dev == nil {
		c.noDXGI = true
		return fmt.Errorf("D3D11CreateDevice: 0x%08x", uint32(hr))
	}
	c.device, c.context = dev, ctx
	return nil
}

func (c *winCapturer) handleOf(m wire.Monitor) uintptr {
	for _, e := range c.monitors {
		if e.mon.ID == m.ID {
			return e.handle
		}
	}
	return 0
}

// duplicate opens IDXGIOutputDuplication for the output showing monitor m.
func (c *winCapturer) duplicate(m wire.Monitor) (*duplication, error) {
	if d := c.dups[m.ID]; d != nil {
		return d, nil
	}
	if err := c.ensureDevice(); err != nil {
		return nil, err
	}
	dxgiDev, err := c.device.query(&iidIDXGIDevice)
	if err != nil {
		return nil, err
	}
	defer dxgiDev.release()
	var adapter *comObj
	if hr := dxgiDev.call(7, uintptr(unsafe.Pointer(&adapter))); int32(hr) < 0 || adapter == nil {
		return nil, fmt.Errorf("IDXGIDevice::GetAdapter: 0x%08x", uint32(hr))
	}
	defer adapter.release()
	want := c.handleOf(m)
	for i := uintptr(0); ; i++ {
		var output *comObj
		hr := adapter.call(7, i, uintptr(unsafe.Pointer(&output)))
		if uint32(hr) == dxgiErrorNotFound || int32(hr) < 0 || output == nil {
			return nil, errDuplicationUnavailable
		}
		var desc dxgiOutputDesc
		output.call(7, uintptr(unsafe.Pointer(&desc)))
		if desc.Monitor != want {
			output.release()
			continue
		}
		out1, err := output.query(&iidIDXGIOutput1)
		output.release()
		if err != nil {
			return nil, err
		}
		var dup *comObj
		hr = out1.call(22, uintptr(unsafe.Pointer(c.device)), uintptr(unsafe.Pointer(&dup)))
		out1.release()
		if int32(hr) < 0 || dup == nil {
			return nil, fmt.Errorf("DuplicateOutput: 0x%08x", uint32(hr))
		}
		d := &duplication{dup: dup}
		c.dups[m.ID] = d
		return d, nil
	}
}

func (c *winCapturer) drop(id int) {
	if d := c.dups[id]; d != nil {
		d.staging.release()
		d.dup.release()
		delete(c.dups, id)
	}
}

func (c *winCapturer) grabDXGI(m wire.Monitor) (*Frame, error) {
	d, err := c.duplicate(m)
	if err != nil {
		return nil, err
	}
	var info outduplFrameInfo
	var res *comObj
	hr := d.dup.call(8, 50, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&res)))
	switch {
	case uint32(hr) == dxgiErrorWaitTimeout:
		return d.last, nil // nothing changed
	case uint32(hr) == dxgiErrorAccessLost:
		c.drop(m.ID) // desktop switch, mode change: re-open on the next frame
		return nil, errors.New("desktop duplication access lost")
	case int32(hr) < 0 || res == nil:
		c.drop(m.ID)
		return nil, fmt.Errorf("AcquireNextFrame: 0x%08x", uint32(hr))
	}
	defer d.dup.call(14) // ReleaseFrame
	defer res.release()
	tex, err := res.query(&iidID3D11Texture2D)
	if err != nil {
		return nil, err
	}
	defer tex.release()
	var desc texture2DDesc
	tex.call(10, uintptr(unsafe.Pointer(&desc)))
	if d.staging == nil || d.desc.Width != desc.Width || d.desc.Height != desc.Height {
		d.staging.release()
		d.staging = nil
		sd := desc
		sd.MipLevels, sd.ArraySize, sd.SampleCount, sd.SampleQuality = 1, 1, 1, 0
		sd.Usage, sd.BindFlags, sd.CPUAccessFlags, sd.MiscFlags = d3d11UsageStaging, 0, d3d11CPUAccessRead, 0
		var st *comObj
		if hr := c.device.call(5, uintptr(unsafe.Pointer(&sd)), 0, uintptr(unsafe.Pointer(&st))); int32(hr) < 0 || st == nil {
			return nil, fmt.Errorf("CreateTexture2D: 0x%08x", uint32(hr))
		}
		d.staging, d.desc = st, desc
	}
	c.context.call(47, uintptr(unsafe.Pointer(d.staging)), uintptr(unsafe.Pointer(tex))) // CopyResource
	var mapped mappedSubresource
	if hr := c.context.call(14, uintptr(unsafe.Pointer(d.staging)), 0, d3d11MapRead, 0,
		uintptr(unsafe.Pointer(&mapped))); int32(hr) < 0 || mapped.Data == nil {
		return nil, fmt.Errorf("Map: 0x%08x", uint32(hr))
	}
	w, h := int(desc.Width), int(desc.Height)
	f := &Frame{W: w, H: h, Stride: w * 4, Pix: make([]byte, w*h*4)}
	src := unsafe.Slice(mapped.Data, int(mapped.RowPitch)*h)
	for y := 0; y < h; y++ {
		copy(f.Pix[y*f.Stride:(y+1)*f.Stride], src[y*int(mapped.RowPitch):])
	}
	c.context.call(15, uintptr(unsafe.Pointer(d.staging)), 0) // Unmap
	d.last = f
	return f, nil
}

type bitmapInfoHeader struct {
	Size          uint32
	Width, Height int32
	Planes        uint16
	BitCount      uint16
	Compression   uint32
	SizeImage     uint32
	XPelsPerMeter int32
	YPelsPerMeter int32
	ClrUsed       uint32
	ClrImportant  uint32
}

func grabGDI(m wire.Monitor) (*Frame, error) {
	screen, _, _ := procGetDC.Call(0)
	if screen == 0 {
		return nil, errors.New("GetDC failed")
	}
	defer func() { _, _, _ = procReleaseDC.Call(0, screen) }()
	mem, _, _ := procCreateCompatibleDC.Call(screen)
	if mem == 0 {
		return nil, errors.New("CreateCompatibleDC failed")
	}
	defer func() { _, _, _ = procDeleteDC.Call(mem) }()
	bi := bitmapInfoHeader{Width: int32(m.W), Height: -int32(m.H), Planes: 1, BitCount: 32}
	bi.Size = uint32(unsafe.Sizeof(bi))
	var bits *byte
	bmp, _, _ := procCreateDIBSection.Call(mem, uintptr(unsafe.Pointer(&bi)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if bmp == 0 || bits == nil {
		return nil, errors.New("CreateDIBSection failed")
	}
	defer func() { _, _, _ = procDeleteObject.Call(bmp) }()
	old, _, _ := procSelectObject.Call(mem, bmp)
	defer func() { _, _, _ = procSelectObject.Call(mem, old) }()
	if r, _, err := procBitBlt.Call(mem, 0, 0, uintptr(m.W), uintptr(m.H), screen, uintptr(m.X), uintptr(m.Y),
		srcCopy|captureBlt); r == 0 {
		return nil, fmt.Errorf("BitBlt: %v", err)
	}
	f := &Frame{W: m.W, H: m.H, Stride: m.W * 4, Pix: make([]byte, m.W*m.H*4)}
	copy(f.Pix, unsafe.Slice(bits, len(f.Pix)))
	return f, nil
}

// Grab captures monitor m.
func (c *winCapturer) Grab(m wire.Monitor) (*Frame, bool, error) {
	if protectedDesktop() {
		c.drop(m.ID)
		return nil, true, nil
	}
	if m.W <= 0 || m.H <= 0 || m.W > 16384 || m.H > 16384 {
		return nil, false, fmt.Errorf("monitor size %dx%d out of range", m.W, m.H)
	}
	f, err := c.grabDXGI(m)
	if err == nil {
		return f, false, nil
	}
	if !errors.Is(err, errDuplicationUnavailable) {
		return nil, false, err
	}
	f, err = grabGDI(m)
	return f, false, err
}

// Close releases every DXGI / D3D11 object.
func (c *winCapturer) Close() {
	for id := range c.dups {
		c.drop(id)
	}
	c.context.release()
	c.device.release()
	c.context, c.device = nil, nil
}
