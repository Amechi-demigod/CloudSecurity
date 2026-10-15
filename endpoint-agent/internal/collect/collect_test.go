package collect

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
)

func TestGuardRecoversPanicsAndErrors(t *testing.T) {
	r := &model.Report{Posture: map[string]model.PostureCheck{}, Errors: map[string]string{}}
	c := collector{r: r}
	c.guard("boom", func() error { panic("kaboom") })
	c.guard("err", func() error { return errors.New("nope") })
	c.posture("p1", func() (model.PostureCheck, error) { panic("bad") })
	c.posture("p2", func() (model.PostureCheck, error) { return model.PostureCheck{}, errors.New("timed out") })
	c.posture("p3", func() (model.PostureCheck, error) { return model.Check("pass", "ok", nil), nil })
	if r.Errors["boom"] == "" || r.Errors["err"] != "nope" || r.Errors["p1"] == "" || r.Errors["p2"] != "timed out" {
		t.Errorf("errors %v", r.Errors)
	}
	if r.Posture["p1"].Status != "unknown" || r.Posture["p2"].Status != "unknown" || *r.Posture["p2"].Error != "timed out" {
		t.Errorf("posture %v", r.Posture)
	}
	if r.Posture["p3"].Status != "pass" {
		t.Error("p3")
	}
}

func TestRunTimeout(t *testing.T) {
	if _, err := Run(context.Background(), 50*time.Millisecond, "/nonexistent/binary"); err == nil {
		t.Error("expected error for missing binary")
	}
}

func TestHashMachineID(t *testing.T) {
	a := HashMachineID("ABC-123")
	if len(a) != 64 || a != HashMachineID(" abc-123 ") || HashMachineID("") != "" {
		t.Errorf("hash %q", a)
	}
}

// TestCollectSmoke runs the real collectors of the current OS (CI runs this on
// Windows and macOS runners). It must never panic and must yield valid JSON.
func TestCollectSmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	r := Collect(context.Background(), Options{Software: true})
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if r.Device.Hostname == "" || r.Device.OSFamily == "" {
		t.Fatalf("missing basics: %s", b)
	}
	t.Logf("collected %d bytes, %d posture checks, %d apps, errors: %v", len(b), len(r.Posture), len(r.Software), r.Errors)
}
