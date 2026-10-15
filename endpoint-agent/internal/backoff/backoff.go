// Package backoff computes check-in schedules: a jittered regular interval and
// exponential backoff with full jitter after failures.
package backoff

import (
	"math/rand/v2"
	"time"
)

// Policy describes retry behaviour.
type Policy struct {
	Base   time.Duration // first retry delay (before jitter)
	Max    time.Duration // cap for the exponential delay
	Jitter float64       // +/- fraction applied to regular intervals (0.1 = 10%)
	Rand   func() float64
}

// Default is used by the agent: 30s, 1m, 2m ... capped at 30m.
var Default = Policy{Base: 30 * time.Second, Max: 30 * time.Minute, Jitter: 0.1}

func (p Policy) rnd() float64 {
	if p.Rand != nil {
		return p.Rand()
	}
	return rand.Float64() //nolint:gosec // scheduling jitter, not security
}

// Retry returns the delay before retry number `attempt` (1-based) after
// consecutive failures: a uniformly random value in [Base/2, min(Max, Base*2^(attempt-1))].
func (p Policy) Retry(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	ceiling := p.Base
	for i := 1; i < attempt && ceiling < p.Max; i++ {
		ceiling *= 2
	}
	if ceiling > p.Max {
		ceiling = p.Max
	}
	floor := p.Base / 2
	if floor > ceiling {
		floor = ceiling
	}
	return floor + time.Duration(p.rnd()*float64(ceiling-floor))
}

// Next returns a regular interval with +/- Jitter applied, so a fleet that was
// installed at the same time does not check in in lock-step.
func (p Policy) Next(interval time.Duration) time.Duration {
	if interval <= 0 {
		return interval
	}
	j := (p.rnd()*2 - 1) * p.Jitter
	return time.Duration(float64(interval) * (1 + j))
}
