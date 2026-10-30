//go:build windows

package helper

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"runtime"

	"golang.org/x/sys/windows"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/remote/wire"
)

var (
	user32                            = windows.NewLazySystemDLL("user32.dll")
	procSetProcessDpiAwarenessContext = user32.NewProc("SetProcessDpiAwarenessContext")
)

var pipeRe = regexp.MustCompile(`^\\\\\.\\pipe\\cnapp-remote-[0-9a-f]{32}$`)

// openPipe opens one end of the service's pipe pair and checks that it is
// owned by SYSTEM: only the service can have created it (a pipe someone else
// created first would make the service's CreateNamedPipe fail, since it uses
// FILE_FLAG_FIRST_PIPE_INSTANCE).
func openPipe(name string, access uint32) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, access, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", name, err)
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		_ = windows.CloseHandle(h)
		return nil, fmt.Errorf("reading the pipe owner: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.IsWellKnown(windows.WinLocalSystemSid) {
		_ = windows.CloseHandle(h)
		return nil, fmt.Errorf("refusing a pipe not owned by SYSTEM")
	}
	return os.NewFile(uintptr(h), name), nil
}

// Run is `cnapp-agent remote-helper --pipe NAME`, started by the service in
// the user's session. It only talks to the service's SYSTEM-owned pipes, and
// takes its parameters from them (not from the command line).
func Run(pipe string) int {
	if !pipeRe.MatchString(pipe) {
		fmt.Fprintln(os.Stderr, "remote-helper: invalid pipe name")
		return 2
	}
	// Capture (D3D11 / DXGI) and input stay on one OS thread.
	runtime.LockOSThread()
	// Per-monitor DPI aware: capture and input work in physical pixels.
	const perMonitorAwareV2 = ^uintptr(3) // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 (-4)
	_, _, _ = procSetProcessDpiAwarenessContext.Call(perMonitorAwareV2)

	in, err := openPipe(pipe+"-out", windows.GENERIC_READ) // service -> helper
	if err != nil {
		fmt.Fprintln(os.Stderr, "remote-helper:", err)
		return 1
	}
	defer in.Close()
	out, err := openPipe(pipe+"-in", windows.GENERIC_WRITE) // helper -> service
	if err != nil {
		fmt.Fprintln(os.Stderr, "remote-helper:", err)
		return 1
	}
	defer out.Close()
	kind, data, err := wire.ReadFrame(in)
	if err != nil || kind != wire.KindJSON {
		fmt.Fprintln(os.Stderr, "remote-helper: no session parameters")
		return 1
	}
	m, err := wire.Decode(data)
	if err != nil || m.T != "params" || m.Params == nil {
		fmt.Fprintln(os.Stderr, "remote-helper: invalid session parameters")
		return 1
	}
	link := NewStreamLink(in, out)
	ui, err := newWinUI()
	if err != nil {
		_ = link.Send(wire.Msg{T: "error", Code: "ERR_HELPER", Detail: "user interface: " + err.Error()})
		return 1
	}
	capt := newCapturer()
	inj := newInjector()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	RunSession(ctx, link, *m.Params, ui, capt, inj, Options{})
	return 0
}
