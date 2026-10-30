//go:build windows && !remote_fake

package remote

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/remote/wire"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/usersession"
)

func systemOnlyPipe(t *testing.T, sddl string) (string, windows.Handle) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	name, err := pipeName()
	if err != nil {
		t.Fatal(err)
	}
	h, err := createPipe(name, true, sa)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = windows.CloseHandle(h) })
	return name, h
}

// A local user (here: the test, not SYSTEM) cannot open the helper pipe.
func TestHelperPipeRefusesOtherUsers(t *testing.T) {
	if usersession.IsLocalSystem() {
		t.Skip("running as SYSTEM")
	}
	// (The creator owns it here; owner rights do not include read / write.)
	name, _ := systemOnlyPipe(t, "D:P(A;;GA;;;SY)")
	p, _ := windows.UTF16PtrFromString(name)
	h, err := windows.CreateFile(p, windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err == nil {
		_ = windows.CloseHandle(h)
		t.Fatal("a non-SYSTEM process opened the SYSTEM-only pipe")
	}
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Logf("open failed with %v (expected access denied)", err)
	}
}

// The service only accepts the helper process it started (by process id).
func TestHelperPipeRefusesAnotherProcess(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	name, h := systemOnlyPipe(t, "D:P(A;;GA;;;SY)(A;;GRGW;;;"+user.User.Sid.String()+")")
	go func() {
		time.Sleep(100 * time.Millisecond)
		p, _ := windows.UTF16PtrFromString(name)
		if c, err := windows.CreateFile(p, windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0); err == nil {
			time.Sleep(500 * time.Millisecond)
			_ = windows.CloseHandle(c)
		}
	}()
	err = connect(context.Background(), h, 0, 1 /* not this process */, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "unexpected pipe client") {
		t.Fatalf("got %v", err)
	}
}

// A second pipe with the same name cannot be created (no squatting).
func TestHelperPipeNameCannotBeSquatted(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sddl := "D:P(A;;GA;;;SY)(A;;GA;;;" + user.User.Sid.String() + ")"
	name, _ := systemOnlyPipe(t, sddl)
	sd, _ := windows.SecurityDescriptorFromString(sddl)
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	if h, err := createPipe(name, true, sa); err == nil {
		_ = windows.CloseHandle(h)
		t.Fatal("FILE_FLAG_FIRST_PIPE_INSTANCE did not prevent a second instance")
	}
}

// A helper that never connects cannot hang Launch (and with it the agent's
// command loop): the wait ends at the timeout, when the helper exits, or when
// the agent stops. Both pipe directions.
func TestHelperThatNeverConnects(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sddl := "D:P(A;;GA;;;SY)(A;;GRGW;;;" + user.User.Sid.String() + ")"
	newPipe := func(inbound bool) windows.Handle {
		sd, _ := windows.SecurityDescriptorFromString(sddl)
		sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
		sa.Length = uint32(unsafe.Sizeof(*sa))
		name, _ := pipeName()
		h, err := createPipe(name, inbound, sa)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = windows.CloseHandle(h) })
		return h
	}
	within := func(t *testing.T, limit time.Duration, want string, f func() error) {
		t.Helper()
		start := time.Now()
		err := f()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("got %v, want %q", err, want)
		}
		if d := time.Since(start); d > limit {
			t.Fatalf("took %v", d)
		}
	}
	for _, inbound := range []bool{true, false} {
		within(t, 3*time.Second, "did not connect in time", func() error {
			return connect(context.Background(), newPipe(inbound), 0, 1, 500*time.Millisecond)
		})
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(200*time.Millisecond, cancel)
		within(t, 3*time.Second, "cancelled", func() error {
			return connect(ctx, newPipe(inbound), 0, 1, time.Minute)
		})
		cmd := exec.Command("cmd.exe", "/c", "ping", "-n", "2", "127.0.0.1")
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		proc, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(cmd.Process.Pid))
		if err != nil {
			t.Fatal(err)
		}
		within(t, 15*time.Second, "exited before connecting", func() error {
			return connect(context.Background(), newPipe(inbound), proc, uint32(cmd.Process.Pid), time.Minute)
		})
		_ = windows.CloseHandle(proc)
		_ = cmd.Wait()
	}
}

// Close stops readLoop even when nobody drains the events any more (the
// controller stopped reading): no goroutine is left blocked on the channel.
func TestPipeHelperReadLoopStopsOnClose(t *testing.T) {
	var frame bytes.Buffer
	_ = wire.NewWriter(&frame).WriteMsg(wire.Msg{T: "stats"})
	h := &pipeHelper{r: io.NopCloser(&endless{frame: frame.Bytes()}), events: make(chan Event),
		done: make(chan struct{})}
	stopped := make(chan struct{})
	go func() {
		h.readLoop()
		close(stopped)
	}()
	<-h.events // it is reading
	close(h.done)
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("readLoop is still blocked after Close")
	}
}

// endless repeats one frame forever.
type endless struct {
	frame []byte
	off   int
}

func (e *endless) Read(p []byte) (int, error) {
	n := copy(p, e.frame[e.off:])
	e.off = (e.off + n) % len(e.frame)
	return n, nil
}
