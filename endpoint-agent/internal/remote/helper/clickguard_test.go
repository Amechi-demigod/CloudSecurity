package helper

import (
	"testing"
	"time"
)

func TestConsentNeedsARealPressAndReleaseOnTheSameButton(t *testing.T) {
	t0 := time.Unix(1000, 0)
	g := clickGuard{strict: true, settle: time.Second}
	g.show(t0)
	later := t0.Add(2 * time.Second)

	// A bare release (PostMessage(WM_LBUTTONUP), or a drag that ends here) does nothing.
	if got := g.up("allow", true); got != "" {
		t.Fatalf("bare release clicked %q", got)
	}
	// Press and release on Allow with a real mouse: allowed.
	g.down("allow", true, later)
	if got := g.up("allow", true); got != "allow" {
		t.Fatalf("real click gave %q", got)
	}
	// Injected or posted messages (no hardware source) never answer.
	g.down("allow", false, later)
	if got := g.up("allow", false); got != "" {
		t.Fatalf("injected click gave %q", got)
	}
	g.down("allow", true, later)
	if got := g.up("allow", false); got != "" {
		t.Fatalf("real press with a forged release gave %q", got)
	}
	// Press on Deny, release on Allow: nothing.
	g.down("deny", true, later)
	if got := g.up("allow", true); got != "" {
		t.Fatalf("press on deny, release on allow gave %q", got)
	}
	// Presses within the first second after the prompt appeared are ignored.
	g.show(later)
	g.down("allow", true, later.Add(500*time.Millisecond))
	if got := g.up("allow", true); got != "" {
		t.Fatalf("click right after the prompt appeared gave %q", got)
	}
	g.down("allow", true, later.Add(1100*time.Millisecond))
	if got := g.up("allow", true); got != "allow" {
		t.Fatalf("click after the settle time gave %q", got)
	}
}

func TestEndSessionStaysEasy(t *testing.T) {
	g := clickGuard{} // the indicator: not strict
	g.show(time.Now())
	g.down("end", false, time.Now()) // injected by an assistive tool, at once
	if got := g.up("end", false); got != "end" {
		t.Fatalf("End session needs %q", got)
	}
	if got := g.up("end", true); got != "" {
		t.Fatalf("a release without a press still ends: %q", got)
	}
}
