package state

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	p := Resolve(t.TempDir())
	if _, err := Load(p); err != ErrNotEnrolled {
		t.Fatalf("expected ErrNotEnrolled, got %v", err)
	}
	s := &State{ServerURL: "https://x.example", DeviceID: "abc", DeviceSecret: "cnd_secret", CheckInIntervalSeconds: 900}
	if err := Save(p, s); err != nil {
		t.Fatal(err)
	}
	s.CheckInIntervalSeconds = 600
	if err := Save(p, s); err != nil { // overwrite
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil || got.DeviceSecret != "cnd_secret" || got.CheckInIntervalSeconds != 600 {
		t.Fatalf("got %+v %v", got, err)
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(p.StateFile())
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("state file mode %v", st.Mode().Perm())
		}
		dt, _ := os.Stat(p.StateDir)
		if dt.Mode().Perm() != 0o700 {
			t.Fatalf("state dir mode %v", dt.Mode().Perm())
		}
	}
	if got.Redacted().DeviceSecret != "<redacted>" || got.DeviceSecret != "cnd_secret" {
		t.Fatal("redaction")
	}
	if err := Remove(p); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err != ErrNotEnrolled {
		t.Fatal("not removed")
	}
}

func TestValidateServerURL(t *testing.T) {
	cases := []struct {
		in       string
		insecure bool
		want     string
		errPart  string
	}{
		{"https://cnapp.example.com/", false, "https://cnapp.example.com", ""},
		{" https://cnapp.example.com/sub/ ", false, "https://cnapp.example.com/sub", ""},
		{"http://localhost:8000", false, "", "refusing plain http"},
		{"http://localhost:8000", true, "http://localhost:8000", ""},
		{"ftp://x", true, "", "unsupported"},
		{"https://user:pw@x", false, "", "credentials"},
		{"not a url", false, "", "invalid"},
	}
	for _, c := range cases {
		got, err := ValidateServerURL(c.in, c.insecure)
		if c.errPart != "" {
			if err == nil || !strings.Contains(err.Error(), c.errPart) {
				t.Errorf("%q: want error %q, got %v", c.in, c.errPart, err)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%q: got %q %v", c.in, got, err)
		}
	}
}

func TestMarkExecuted(t *testing.T) {
	s := &State{}
	if !s.MarkExecuted("a") || s.MarkExecuted("a") {
		t.Fatal("replay guard")
	}
	for i := 0; i < MaxExecuted+10; i++ {
		s.MarkExecuted(string(rune('A'+i%26)) + strings.Repeat("x", i))
	}
	if len(s.ExecutedCommands) != MaxExecuted {
		t.Fatalf("len %d", len(s.ExecutedCommands))
	}
}
