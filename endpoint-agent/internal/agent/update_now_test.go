package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/update"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/version"
)

const testOffer = `{"release_id":"r1","version":"1.1.0","manifest_path":"/api/agent/updates/releases/r1/manifest",` +
	`"artifact_path":"/api/agent/updates/releases/r1/artifacts/darwin/arm64","health_timeout_seconds":600,"jitter_seconds":900}`

func TestOfferDelay(t *testing.T) {
	o := update.Offer{ReleaseID: "r1", JitterSeconds: 900}
	for i := 0; i < 50; i++ {
		if d := offerDelay(o, false); d < 0 || d > 900*time.Second {
			t.Fatalf("random jitter %s out of range", d)
		}
	}
	if d := offerDelay(o, true); d != 0 {
		t.Errorf("forced (check_for_update): %s, want 0", d)
	}
	o.Immediate, o.JitterSeconds = true, 40
	if d := offerDelay(o, false); d != 40*time.Second {
		t.Errorf("immediate with server stagger: %s, want exactly 40s", d)
	}
	o.JitterSeconds = 99999
	if d := offerDelay(o, true); d != maxImmediateDelay {
		t.Errorf("immediate stagger is capped: %s", d)
	}
	if d := offerDelay(update.Offer{JitterSeconds: 0}, false); d != 0 {
		t.Errorf("no jitter: %s", d)
	}
}

func TestScheduleOfferUpdateNowBringsForward(t *testing.T) {
	a := &Agent{}
	now := time.Now()
	o := update.Offer{ReleaseID: "r1", Version: "1.1.0", JitterSeconds: 900}
	a.scheduleOffer(&o, now)
	// Pin the random first schedule for a deterministic test: 10 min from now.
	a.nextUpdate = now.Add(10 * time.Minute)
	first := a.nextUpdate
	// The same offer at a later regular check-in keeps its time.
	a.scheduleOffer(&o, now.Add(time.Minute))
	if !a.nextUpdate.Equal(first) {
		t.Fatal("regular re-offer must keep the scheduled time")
	}
	// "Update now" from the server (immediate) moves it to now (+ stagger).
	im := o
	im.Immediate, im.JitterSeconds = true, 0
	a.scheduleOffer(&im, now.Add(2*time.Minute))
	if !a.nextUpdate.Equal(now.Add(2 * time.Minute)) {
		t.Fatalf("immediate offer not brought forward: %s", a.nextUpdate.Sub(now))
	}
	// An immediate offer never postpones an earlier schedule.
	a.scheduleOffer(&im, now.Add(3*time.Minute))
	if !a.nextUpdate.Equal(now.Add(2 * time.Minute)) {
		t.Fatal("immediate offer postponed the update")
	}
	// No offer clears the schedule.
	a.scheduleOffer(nil, now)
	if a.offer != nil {
		t.Fatal("offer not cleared")
	}
}

func TestCheckForUpdateCommandSkipsJitter(t *testing.T) {
	a, f := setup(t)
	// Self-update disabled (foreground run): the command fails clearly.
	if _, err := a.CheckForUpdate(context.Background()); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("without updater: %v", err)
	}
	a.Updater = &update.Updater{Current: "1.0.0", Paths: a.Paths}
	f.offer = testOffer
	// A regular check-in schedules the offer with a random delay of up to 900s.
	if err := a.CheckIn(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.features != version.Features {
		t.Errorf("features header %q", f.features)
	}
	// The remote command checks in again and starts the same release now.
	a.handle(context.Background(), command("c-upd", "check_for_update", nil))
	if f.results["c-upd"] != "succeeded" || !strings.Contains(f.outputs["c-upd"], "1.1.0") {
		t.Fatalf("result %q %q", f.results["c-upd"], f.outputs["c-upd"])
	}
	w, ok := a.updateWait()
	if !ok || w > time.Second {
		t.Fatalf("update not due now after check_for_update (wait %s, scheduled %v)", w, ok)
	}
	if a.forceUpdate {
		t.Error("forceUpdate left set")
	}
	// Nothing offered: the command still succeeds and says so.
	f.offer = ""
	a.handle(context.Background(), command("c-none", "check_for_update", nil))
	if f.results["c-none"] != "succeeded" || !strings.Contains(f.outputs["c-none"], "no update offered") {
		t.Fatalf("result %q %q", f.results["c-none"], f.outputs["c-none"])
	}
}
