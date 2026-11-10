package netscan

import (
	"context"
	"sync"
	"time"
)

// Limiter spaces packets so the whole scan stays under a global rate cap.
type Limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

// RateFor is the global packet cap for a concurrency level: about 200
// packets/s at the default concurrency of 20, 500 at 64.
func RateFor(concurrency int) int {
	if concurrency > 20 {
		return 500
	}
	return 200
}

// NewLimiter allows perSecond events per second (<= 0: unlimited).
func NewLimiter(perSecond int) *Limiter {
	l := &Limiter{}
	if perSecond > 0 {
		l.interval = time.Second / time.Duration(perSecond)
	}
	return l
}

// Wait blocks until the caller may send one packet, or ctx ends.
func (l *Limiter) Wait(ctx context.Context) error {
	if l == nil || l.interval == 0 {
		return ctx.Err()
	}
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	at := l.next
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()
	d := time.Until(at)
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
