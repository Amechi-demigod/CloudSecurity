//go:build windows && !remote_fake

package remote

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/remote/wire"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/usersession"
)

// DefaultPlatform is the Windows backend: the helper is this same binary
// (`cnapp-agent remote-helper --pipe NAME`) started in the signed-in user's
// session with CreateProcessAsUser, inside a kill-on-close Job object.
//
// The service and the helper talk over two one-way named pipes whose DACL
// allows only SYSTEM and the session's user, created with
// FILE_FLAG_FIRST_PIPE_INSTANCE (no one can squat the name) and
// PIPE_REJECT_REMOTE_CLIENTS. The service only accepts the client whose
// process id is the helper it started; the helper only talks to a pipe owned
// by SYSTEM. Session parameters go over the pipe, never on the command line,
// so a local user cannot start a capture session for someone else.
func DefaultPlatform() Platform { return &winPlatform{} }

type winPlatform struct {
	mu      sync.Mutex
	session uint32
}

var (
	sasDLL      = windows.NewLazySystemDLL("sas.dll")
	procSendSAS = sasDLL.NewProc("SendSAS")
)

func (w *winPlatform) target() (uint32, error) {
	sid, err := usersession.Attended()
	if err != nil {
		return 0, Errorf(ErrNoAttendedUser, "nobody is signed in to this device (%v)", err)
	}
	active, locked, err := usersession.State(sid)
	if err != nil {
		return 0, Errorf(ErrNoAttendedUser, "cannot read the session state: %v", err)
	}
	if !active {
		return 0, Errorf(ErrNoAttendedUser, "the user's session is disconnected")
	}
	if locked {
		return 0, Errorf(ErrNoAttendedUser, "the screen is locked; unattended access is not supported")
	}
	return sid, nil
}

func (w *winPlatform) Preflight(context.Context) error {
	if !usersession.IsLocalSystem() {
		return Errorf(ErrHelper, "remote sessions need the agent running as its Windows service")
	}
	_, err := w.target()
	return err
}

func pipeName() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return `\\.\pipe\cnapp-remote-` + hex.EncodeToString(b[:]), nil
}

func createPipe(name string, inbound bool, sa *windows.SecurityAttributes) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	access := uint32(windows.PIPE_ACCESS_OUTBOUND)
	if inbound {
		access = windows.PIPE_ACCESS_INBOUND
	}
	return windows.CreateNamedPipe(p, access|windows.FILE_FLAG_FIRST_PIPE_INSTANCE,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
		1, 1<<20, 1<<20, 0, sa)
}

// connect waits for the helper to open `h` and checks it is that helper.
func connect(h windows.Handle, name string, pid uint32, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() {
		err := windows.ConnectNamedPipe(h, nil)
		if errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
			err = nil
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("ConnectNamedPipe: %w", err)
		}
	case <-time.After(timeout):
		// Unblock ConnectNamedPipe with our own client; the PID check below rejects it.
		if p, err := windows.UTF16PtrFromString(name); err == nil {
			if c, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
				windows.OPEN_EXISTING, 0, 0); err == nil {
				_ = windows.CloseHandle(c)
			}
		}
		<-done
		return errors.New("the helper did not connect in time")
	}
	var got uint32
	if err := windows.GetNamedPipeClientProcessId(h, &got); err != nil {
		return fmt.Errorf("GetNamedPipeClientProcessId: %w", err)
	}
	if got != pid {
		return fmt.Errorf("unexpected pipe client (process %d, expected %d)", got, pid)
	}
	return nil
}

func (w *winPlatform) Launch(ctx context.Context, p Params) (Helper, error) {
	sid, err := w.target()
	if err != nil {
		return nil, err
	}
	user, err := usersession.UserSID(sid)
	if err != nil {
		return nil, Errorf(ErrNoAttendedUser, "%v", err)
	}
	sd, err := windows.SecurityDescriptorFromString(
		fmt.Sprintf("O:SYG:SYD:P(A;;GA;;;SY)(A;;GRGW;;;%s)", user.String()))
	if err != nil {
		return nil, Errorf(ErrHelper, "pipe security descriptor: %v", err)
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	name, err := pipeName()
	if err != nil {
		return nil, Errorf(ErrHelper, "%v", err)
	}
	in, err := createPipe(name+"-in", true, sa) // helper -> service
	if err != nil {
		return nil, Errorf(ErrHelper, "creating the helper pipe: %v", err)
	}
	out, err := createPipe(name+"-out", false, sa) // service -> helper
	if err != nil {
		_ = windows.CloseHandle(in)
		return nil, Errorf(ErrHelper, "creating the helper pipe: %v", err)
	}
	exe, err := os.Executable()
	if err != nil {
		_ = windows.CloseHandle(in)
		_ = windows.CloseHandle(out)
		return nil, Errorf(ErrHelper, "%v", err)
	}
	proc, err := usersession.Launch(sid, exe, fmt.Sprintf(`"%s" remote-helper --pipe %s`, exe, name),
		usersession.Options{KillOnClose: true, NoWindow: true})
	if err != nil {
		_ = windows.CloseHandle(in)
		_ = windows.CloseHandle(out)
		return nil, Errorf(ErrHelper, "starting the helper: %v", err)
	}
	h := &pipeHelper{proc: proc, events: make(chan Event, 32)}
	fail := func(err error) (Helper, error) {
		_ = windows.CloseHandle(in)
		_ = windows.CloseHandle(out)
		_ = proc.Close()
		return nil, Errorf(ErrHelper, "%v", err)
	}
	if err := connect(out, name+"-out", proc.PID, 20*time.Second); err != nil {
		return fail(err)
	}
	if err := connect(in, name+"-in", proc.PID, 5*time.Second); err != nil {
		return fail(err)
	}
	h.r = os.NewFile(uintptr(in), name+"-in")
	h.wf = os.NewFile(uintptr(out), name+"-out")
	h.w = wire.NewWriter(h.wf)
	wp := p.WireParams()
	if err := h.w.WriteMsg(wire.Msg{T: "params", Params: &wp}); err != nil {
		_ = h.Close()
		return nil, Errorf(ErrHelper, "sending the session parameters: %v", err)
	}
	w.mu.Lock()
	w.session = sid
	w.mu.Unlock()
	go h.readLoop()
	return h, nil
}

// Watch polls the session once a second: a switch to another user (fast user
// switching), an RDP disconnect or a locked screen ends the session cleanly.
func (w *winPlatform) Watch(ctx context.Context) <-chan string {
	w.mu.Lock()
	sid := w.session
	w.mu.Unlock()
	ch := make(chan string, 1)
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			reason := ""
			if cur, err := usersession.Attended(); err != nil || cur != sid {
				reason = "session_switch"
			} else if active, locked, err := usersession.State(sid); err != nil || !active {
				reason = "session_switch"
			} else if locked {
				reason = "user_locked"
			}
			if reason != "" {
				ch <- reason
				return
			}
		}
	}()
	return ch
}

// SendSAS simulates Ctrl+Alt+Del (sas.dll, called by the LocalSystem
// service). Windows only honours it when the SoftwareSASGeneration policy
// allows services (1 or 3); the agent never changes that policy itself.
func (w *winPlatform) SendSAS() error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, registry.QUERY_VALUE)
	if err != nil {
		return errors.New("the SoftwareSASGeneration policy is not set (Ctrl+Alt+Del from services is off)")
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("SoftwareSASGeneration")
	if err != nil || (v != 1 && v != 3) {
		return errors.New("the SoftwareSASGeneration policy does not allow services to send Ctrl+Alt+Del")
	}
	if err := procSendSAS.Find(); err != nil {
		return fmt.Errorf("sas.dll: %w", err)
	}
	_, _, _ = procSendSAS.Call(0) // FALSE: called from a service
	return nil
}

type pipeHelper struct {
	proc   *usersession.Process
	r, wf  *os.File
	w      *wire.Writer
	events chan Event
	once   sync.Once
}

func (h *pipeHelper) Events() <-chan Event { return h.events }

func (h *pipeHelper) readLoop() {
	defer close(h.events)
	for {
		kind, data, err := wire.ReadFrame(h.r)
		if err != nil {
			return
		}
		h.events <- Event{Kind: kind, Data: data}
	}
}

func (h *pipeHelper) Send(m wire.Msg) error { return h.w.WriteMsg(m) }

// Close asks the helper to stop (it stops capture and input first), gives it
// two seconds to remove its windows, then kills it and the Job object.
func (h *pipeHelper) Close() error {
	h.once.Do(func() {
		stopped := make(chan struct{})
		go func() {
			_ = h.w.WriteMsg(wire.Msg{T: "stop"})
			close(stopped)
		}()
		select {
		case <-stopped:
		case <-time.After(time.Second):
		}
		if _, err := h.proc.Wait(2000); err != nil {
			slog.Info("remote-session helper did not exit by itself; terminating it")
		}
		_ = h.proc.Close()
		_ = h.wf.Close()
		_ = h.r.Close()
	})
	return nil
}
