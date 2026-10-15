package backoff

import (
	"testing"
	"time"
)

func fixed(v float64) func() float64 { return func() float64 { return v } }

func TestRetryGrowsAndCaps(t *testing.T) {
	p := Policy{Base: 30 * time.Second, Max: 30 * time.Minute, Rand: fixed(1)}
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute,
		16 * time.Minute, 30 * time.Minute, 30 * time.Minute}
	for i, w := range want {
		if got := p.Retry(i + 1); got != w {
			t.Errorf("attempt %d: got %v want %v", i+1, got, w)
		}
	}
	if got := p.Retry(1000); got != 30*time.Minute {
		t.Errorf("huge attempt: %v", got)
	}
	p.Rand = fixed(0)
	if got := p.Retry(5); got != 15*time.Second {
		t.Errorf("floor: %v", got)
	}
	if got := p.Retry(0); got != 15*time.Second {
		t.Errorf("attempt 0: %v", got)
	}
}

func TestRetryWithinBounds(t *testing.T) {
	p := Default
	for a := 1; a < 20; a++ {
		for i := 0; i < 50; i++ {
			d := p.Retry(a)
			if d < p.Base/2 || d > p.Max {
				t.Fatalf("attempt %d: %v out of bounds", a, d)
			}
		}
	}
}

func TestNextJitter(t *testing.T) {
	p := Policy{Jitter: 0.1, Rand: fixed(1)}
	if got := p.Next(15 * time.Minute); got != 16*time.Minute+30*time.Second {
		t.Errorf("max jitter: %v", got)
	}
	p.Rand = fixed(0)
	if got := p.Next(15 * time.Minute); got != 13*time.Minute+30*time.Second {
		t.Errorf("min jitter: %v", got)
	}
	p.Rand = fixed(0.5)
	if got := p.Next(time.Minute); got != time.Minute {
		t.Errorf("no jitter: %v", got)
	}
}
