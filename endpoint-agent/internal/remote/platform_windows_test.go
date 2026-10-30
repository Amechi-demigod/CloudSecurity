//go:build windows && !remote_fake

package remote

import (
	"errors"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

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
	err = connect(h, name, 1 /* not this process */, 5*time.Second)
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
