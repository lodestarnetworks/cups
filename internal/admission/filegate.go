// Package admission provides fail-closed, operator-controlled admission gates
// for LTE control-plane processes. Existing sessions are never affected by an
// admission gate; callers consult it only before creating new state.
package admission

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

const (
	defaultPollInterval = 250 * time.Millisecond
	minPollInterval     = 25 * time.Millisecond
	maxPollInterval     = 30 * time.Second
)

// Event describes one initial observation, state transition, or filesystem
// failure. A filesystem failure always puts the gate into drain mode.
type Event struct {
	At       time.Time
	Draining bool
	Changed  bool
	Err      error
}

// Stats is a concurrency-safe snapshot of the gate state.
type Stats struct {
	Enabled      bool
	Draining     bool
	Transitions  uint64
	CheckErrors  uint64
	LastCheck    time.Time
	PollInterval time.Duration
}

// FileGate enters drain mode while Path exists. An unexpected stat error is
// treated as draining so an unreadable operator control path cannot silently
// admit new subscribers.
type FileGate struct {
	path         string
	pollInterval time.Duration
	draining     atomic.Bool
	transitions  atomic.Uint64
	checkErrors  atomic.Uint64
	checkFailing atomic.Bool
	lastCheckNS  atomic.Int64
}

// NewFileGate validates an optional absolute control path. An empty path
// disables dynamic draining and always allows new sessions.
func NewFileGate(path string, pollInterval time.Duration) (*FileGate, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		if pollInterval != 0 {
			return nil, errors.New("admission: poll interval requires a drain file")
		}
		return &FileGate{}, nil
	}
	if len(path) > 4096 || !filepath.IsAbs(path) {
		return nil, errors.New("admission: drain file must be an absolute path of at most 4096 bytes")
	}
	path = filepath.Clean(path)
	if path == string(filepath.Separator) {
		return nil, errors.New("admission: filesystem root cannot be used as a drain file")
	}
	if pollInterval == 0 {
		pollInterval = defaultPollInterval
	}
	if pollInterval < minPollInterval || pollInterval > maxPollInterval {
		return nil, errors.New("admission: poll interval must be between 25ms and 30s")
	}
	return &FileGate{path: path, pollInterval: pollInterval}, nil
}

// Enabled reports whether a drain file was configured.
func (g *FileGate) Enabled() bool { return g != nil && g.path != "" }

// AllowNewSession is safe to call in the GTP request hot path.
func (g *FileGate) AllowNewSession() bool {
	return g == nil || !g.draining.Load()
}

// Refresh observes the drain file once. It returns an Event for the initial
// observation, transitions, and errors; unchanged successful checks return
// emit=false.
func (g *FileGate) Refresh() (event Event, emit bool) {
	if g == nil || !g.Enabled() {
		return Event{}, false
	}
	now := time.Now().UTC()
	_, err := os.Lstat(g.path)
	draining := err == nil
	if err != nil {
		if os.IsNotExist(err) {
			err = nil
		} else {
			draining = true
			g.checkErrors.Add(1)
		}
	}
	checkFailed := err != nil
	previousCheckFailed := g.checkFailing.Swap(checkFailed)
	last := g.lastCheckNS.Swap(now.UnixNano())
	previous := g.draining.Swap(draining)
	changed := last != 0 && previous != draining
	if changed {
		g.transitions.Add(1)
	}
	event = Event{At: now, Draining: draining, Changed: changed, Err: err}
	return event, last == 0 || changed || checkFailed != previousCheckFailed
}

// Run polls until ctx is cancelled. observe is called only for the initial
// state, transitions, and errors, keeping logs bounded during normal service.
func (g *FileGate) Run(ctx context.Context, observe func(Event)) {
	if g == nil || !g.Enabled() {
		return
	}
	emit := func() {
		event, ok := g.Refresh()
		if ok && observe != nil {
			observe(event)
		}
	}
	emit()
	ticker := time.NewTicker(g.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			emit()
		case <-ctx.Done():
			return
		}
	}
}

// Stats returns the current state without touching the filesystem.
func (g *FileGate) Stats() Stats {
	if g == nil {
		return Stats{}
	}
	stats := Stats{
		Enabled: g.Enabled(), Draining: g.draining.Load(), Transitions: g.transitions.Load(),
		CheckErrors: g.checkErrors.Load(), PollInterval: g.pollInterval,
	}
	if value := g.lastCheckNS.Load(); value != 0 {
		stats.LastCheck = time.Unix(0, value).UTC()
	}
	return stats
}
