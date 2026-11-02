//go:build windows

package usersession

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// WTSINFOEXW: DWORD Level, then the 8-byte aligned WTSINFOEX_LEVEL1_W
// (SessionId, SessionState, SessionFlags, ...).
func TestWTSInfoExLayout(t *testing.T) {
	var v wtsInfoExLevel1
	for name, got := range map[string]uintptr{
		"SessionID":    unsafe.Offsetof(v.SessionID),
		"SessionState": unsafe.Offsetof(v.SessionState),
		"SessionFlags": unsafe.Offsetof(v.SessionFlags),
	} {
		want := map[string]uintptr{"SessionID": 8, "SessionState": 12, "SessionFlags": 16}[name]
		if got != want {
			t.Errorf("offset of %s = %d, want %d", name, got, want)
		}
	}
}

// Querying this process's own session must round-trip its id (a wrong layout
// reads padding or the wrong field and fails here on any Windows host).
func TestStateReadsOwnSession(t *testing.T) {
	var sid uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &sid); err != nil {
		t.Fatalf("ProcessIdToSessionId: %v", err)
	}
	if _, _, err := State(sid); err != nil {
		t.Fatalf("State(%d): %v", sid, err)
	}
}
