package lostmode

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/state"
)

type fakeBackend struct {
	cur     Notice
	failSet bool
}

func (f *fakeBackend) Name() string                              { return "fake notice" }
func (f *fakeBackend) Get(context.Context) (Notice, error)       { return f.cur, nil }
func (f *fakeBackend) Restore(_ context.Context, n Notice) error { f.cur = n; return nil }
func (f *fakeBackend) Set(_ context.Context, n Notice) error {
	if f.failSet {
		return errors.New("access denied")
	}
	f.cur = n
	return nil
}

func manager(t *testing.T, b *fakeBackend) (*Manager, *int) {
	locks := 0
	m := &Manager{Paths: state.Resolve(t.TempDir()), Backend: b, Now: func() time.Time { return time.Unix(1_800_000_000, 0) },
		Lock: func(context.Context) (string, error) { locks++; return "1 session locked", nil }}
	return m, &locks
}

func TestEnableDisableRestoresPrevious(t *testing.T) {
	orig := Notice{Caption: "Corp policy", CaptionSet: true} // text unset
	b := &fakeBackend{cur: orig}
	m, locks := manager(t, b)
	ctx := context.Background()
	out, err := m.Enable(ctx, "Property of Wakanow", "+234 1 234")
	if err != nil || *locks != 1 || !strings.Contains(out, "1 session locked") {
		t.Fatalf("%q %v locks=%d", out, err, *locks)
	}
	if !strings.Contains(b.cur.Text, "Property of Wakanow") || !strings.Contains(b.cur.Text, "+234 1 234") ||
		b.cur.Caption != "This device has been reported lost" {
		t.Fatalf("notice %+v", b.cur)
	}
	if st := m.Status(); st["active"] != true {
		t.Fatalf("status %v", st)
	}
	// Enabling again keeps the ORIGINAL previous notice.
	if _, err := m.Enable(ctx, "Updated", "123"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := m.Relock(ctx); !ok || *locks != 3 {
		t.Fatalf("relock locks=%d", *locks)
	}
	if _, err := m.Disable(ctx); err != nil {
		t.Fatal(err)
	}
	if b.cur != orig {
		t.Fatalf("not restored: %+v", b.cur)
	}
	if st := m.Status(); st["active"] != false {
		t.Fatalf("status %v", st)
	}
	if ok, _ := m.Relock(ctx); ok {
		t.Fatal("relock while not lost")
	}
	if out, err := m.Disable(ctx); err != nil || !strings.Contains(out, "not active") {
		t.Fatalf("%q %v", out, err)
	}
}

func TestEnableFailureLeavesNoRecord(t *testing.T) {
	b := &fakeBackend{failSet: true}
	m, _ := manager(t, b)
	if _, err := m.Enable(context.Background(), "x", "123"); err == nil {
		t.Fatal("expected error")
	}
	if rec, _ := m.Load(); rec != nil {
		t.Fatal("record left behind")
	}
}

func TestLockFailureKeepsLostMode(t *testing.T) {
	b := &fakeBackend{}
	m, _ := manager(t, b)
	m.Lock = func(context.Context) (string, error) { return "", errors.New("no active interactive session") }
	out, err := m.Enable(context.Background(), "x", "123")
	if err != nil || !strings.Contains(out, "no active interactive session") {
		t.Fatalf("%q %v", out, err)
	}
	if rec, _ := m.Load(); rec == nil {
		t.Fatal("lost mode should stay active")
	}
}
