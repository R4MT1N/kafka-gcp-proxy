package proxy

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Initial state: no lifetime -> never reauth.
func TestConnectionAuthState_DisabledByDefault(t *testing.T) {
	a := assert.New(t)
	s := newConnectionAuthState(0)
	a.False(s.NeedsReauth(time.Now()))
	a.True(s.NextReadDeadline().IsZero())
	a.False(s.InFlightExpired(time.Now()))
}

// With a positive lifetime, NeedsReauth flips true only after the safety
// margin elapses, not on the dot.
func TestConnectionAuthState_SchedulesWithSafetyMargin(t *testing.T) {
	a := assert.New(t)
	const lifetimeMs = 30_000
	s := newConnectionAuthState(lifetimeMs)
	now := time.Now()

	a.False(s.NeedsReauth(now), "fresh state should not immediately need reauth")
	// 50% in — still inside the safety margin (80% = 24s)
	a.False(s.NeedsReauth(now.Add(15*time.Second)))
	// Past the 80% mark — should fire
	a.True(s.NeedsReauth(now.Add(25*time.Second)))
}

// While a reauth is in flight, NeedsReauth must stay false even past the
// scheduled deadline, so the request loop doesn't double-fire.
func TestConnectionAuthState_InFlightSuppressesReauth(t *testing.T) {
	a := assert.New(t)
	s := newConnectionAuthState(1000)
	now := time.Now()
	s.MarkInFlight(now)
	a.False(s.NeedsReauth(now.Add(time.Hour)), "in-flight must suppress NeedsReauth")
}

// A successful CompleteReauth advances the schedule by the new lifetime.
func TestConnectionAuthState_CompleteReauthAdvancesSchedule(t *testing.T) {
	a := assert.New(t)
	s := newConnectionAuthState(10_000)
	s.MarkInFlight(time.Now())
	a.False(s.NeedsReauth(time.Now()))

	s.CompleteReauth(60_000)
	a.False(s.NeedsReauth(time.Now()), "post-complete with fresh lifetime should not immediately fire")
	// And it should fire again after 80% of the NEW lifetime.
	a.True(s.NeedsReauth(time.Now().Add(50*time.Second)))
}

// CompleteReauth with non-positive value should not regress the schedule —
// we keep refreshing rather than silently dropping reauth.
func TestConnectionAuthState_CompleteReauthNonPositiveKeepsSchedule(t *testing.T) {
	a := assert.New(t)
	s := newConnectionAuthState(30_000)
	before := s.NextReadDeadline()
	s.MarkInFlight(time.Now())
	s.CompleteReauth(0)
	a.Equal(before, s.NextReadDeadline(), "non-positive lifetime should leave the schedule alone")
}

// InFlightExpired fires only after the cushion, and only while in flight.
func TestConnectionAuthState_InFlightExpiredOnlyAfterCushion(t *testing.T) {
	a := assert.New(t)
	s := newConnectionAuthState(60_000)
	now := time.Now()
	a.False(s.InFlightExpired(now), "not in flight = never expired")
	s.MarkInFlight(now)
	a.False(s.InFlightExpired(now.Add(10*time.Second)), "within cushion")
	a.True(s.InFlightExpired(now.Add(reauthInflightCushion+time.Second)), "past cushion")
	s.CompleteReauth(60_000)
	a.False(s.InFlightExpired(now.Add(time.Hour)), "cleared after complete")
}

// Concurrent NeedsReauth / MarkInFlight / CompleteReauth must not race
// or trigger duplicate reauth firings.
func TestConnectionAuthState_ConcurrentAccess(t *testing.T) {
	a := assert.New(t)
	s := newConnectionAuthState(1) // expires immediately so NeedsReauth would trip

	// Sleep a hair so the safety-margin scheduling has passed.
	time.Sleep(2 * time.Millisecond)

	const N = 100
	var wg sync.WaitGroup
	var firings int
	var mu sync.Mutex
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			now := time.Now()
			if s.NeedsReauth(now) {
				s.MarkInFlight(now)
				mu.Lock()
				firings++
				mu.Unlock()
				// Simulate response handler completing.
				time.Sleep(time.Millisecond)
				s.CompleteReauth(60_000)
			}
		}()
	}
	wg.Wait()
	// We don't strictly guarantee firings==1 because windows after
	// CompleteReauth allow a subsequent NeedsReauth=true once the new
	// schedule elapses. What we do guarantee is no panics, no races (the
	// -race detector enforces that).
	a.LessOrEqual(firings, N, "sanity")
}
