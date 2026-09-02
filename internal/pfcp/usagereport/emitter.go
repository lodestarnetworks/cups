package usagereport

import (
	"context"
	"errors"
	"sync"
	"time"
)

type Measurement struct {
	UPSEID          uint64
	URRID           uint32
	UplinkPackets   uint64
	DownlinkPackets uint64
	UplinkBytes     uint64
	DownlinkBytes   uint64
	ThresholdEvents uint64
	FirstPacket     time.Time
	LastPacket      time.Time
}

type EmitterConfig struct {
	PollInterval  time.Duration
	ReportTimeout time.Duration
	RetryBase     time.Duration
	RetryMax      time.Duration
	QueueSize     int
	Workers       int
	Snapshot      func() []Measurement
	ResolveCPSEID func(upSEID uint64) (uint64, bool)
	Send          func(context.Context, uint64, Report) error
}

type EmitterStats struct {
	ReportsGenerated uint64
	ReportsSent      uint64
	ReportsRetried   uint64
	ReportsFailed    uint64
	QueueFull        uint64
	CounterResets    uint64
	PendingReports   uint64
	TrackedURRs      uint64
}

type emitterKey struct {
	upSEID uint64
	urrID  uint32
}

type emitterState struct {
	baseline         Measurement
	intervalStart    time.Time
	nextSequence     uint32
	pending          *Report
	scheduled        bool
	attempts         int
	nextAttempt      time.Time
	observedThisPoll bool
}

type deliveryJob struct {
	key    emitterKey
	report Report
}

type deliveryResult struct {
	key      emitterKey
	sequence uint32
	err      error
}

type Emitter struct {
	config  EmitterConfig
	jobs    chan deliveryJob
	results chan deliveryResult

	mu     sync.Mutex
	states map[emitterKey]*emitterState
	stats  EmitterStats
}

func NewEmitter(config EmitterConfig) (*Emitter, error) {
	if config.Snapshot == nil || config.ResolveCPSEID == nil || config.Send == nil {
		return nil, errors.New("PFCP usage emitter requires snapshot, resolver, and sender callbacks")
	}
	if config.PollInterval == 0 {
		config.PollInterval = time.Second
	}
	if config.ReportTimeout == 0 {
		config.ReportTimeout = 5 * time.Second
	}
	if config.RetryBase == 0 {
		config.RetryBase = 250 * time.Millisecond
	}
	if config.RetryMax == 0 {
		config.RetryMax = 30 * time.Second
	}
	if config.QueueSize == 0 {
		config.QueueSize = 4096
	}
	if config.Workers == 0 {
		config.Workers = 8
	}
	if config.PollInterval < 10*time.Millisecond || config.ReportTimeout <= 0 || config.RetryBase <= 0 ||
		config.RetryMax < config.RetryBase || config.QueueSize < 1 || config.Workers < 1 || config.Workers > 256 {
		return nil, errors.New("invalid PFCP usage emitter configuration")
	}
	return &Emitter{
		config: config, jobs: make(chan deliveryJob, config.QueueSize),
		results: make(chan deliveryResult, config.QueueSize+config.Workers),
		states:  make(map[emitterKey]*emitterState),
	}, nil
}

func (e *Emitter) Run(ctx context.Context) {
	var workers sync.WaitGroup
	for index := 0; index < e.config.Workers; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			e.worker(ctx)
		}()
	}
	e.poll(time.Now())
	ticker := time.NewTicker(e.config.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case result := <-e.results:
			e.complete(result, time.Now())
		case now := <-ticker.C:
			e.drainResults(now)
			e.poll(now)
		case <-ctx.Done():
			workersStopped := make(chan struct{})
			go func() {
				workers.Wait()
				close(workersStopped)
			}()
			// A sender can complete at the same instant shutdown is requested.
			// Continue draining while workers stop so result publication cannot
			// block and successful delivery is not left marked pending.
			for {
				select {
				case result := <-e.results:
					e.complete(result, time.Now())
				case <-workersStopped:
					e.drainResults(time.Now())
					return
				}
			}
		}
	}
}

func (e *Emitter) Stats() EmitterStats {
	e.mu.Lock()
	defer e.mu.Unlock()
	stats := e.stats
	stats.TrackedURRs = uint64(len(e.states))
	for _, state := range e.states {
		if state.pending != nil {
			stats.PendingReports++
		}
	}
	return stats
}

func (e *Emitter) poll(now time.Time) {
	measurements := e.config.Snapshot()
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, state := range e.states {
		state.observedThisPoll = false
	}
	for _, measurement := range measurements {
		if measurement.UPSEID == 0 || measurement.URRID == 0 {
			continue
		}
		key := emitterKey{upSEID: measurement.UPSEID, urrID: measurement.URRID}
		state := e.states[key]
		if state == nil {
			start := canonicalUsageTime(measurement.FirstPacket)
			if start.IsZero() {
				start = canonicalUsageTime(now)
			}
			state = &emitterState{intervalStart: start}
			e.states[key] = state
		}
		state.observedThisPoll = true
		if countersDecreased(measurement, state.baseline) && state.pending == nil {
			state.baseline = measurement
			state.intervalStart = canonicalUsageTime(now)
			e.stats.CounterResets++
			continue
		}
		if state.pending == nil && measurement.ThresholdEvents > state.baseline.ThresholdEvents {
			cpSEID, ready := e.config.ResolveCPSEID(measurement.UPSEID)
			if ready && cpSEID != 0 {
				report := makeIntervalReport(cpSEID, state.nextSequence, state.intervalStart, state.baseline, measurement, now)
				if report.TotalBytes() != 0 {
					state.pending = &report
					state.nextSequence++
					state.baseline = measurement
					state.intervalStart = report.EndTime
					state.attempts = 0
					state.nextAttempt = time.Time{}
					e.stats.ReportsGenerated++
				}
			}
		}
		e.scheduleLocked(key, state, now)
	}
	for key, state := range e.states {
		if !state.observedThisPoll && state.pending == nil {
			delete(e.states, key)
			continue
		}
		if state.pending != nil {
			e.scheduleLocked(key, state, now)
		}
	}
}

func (e *Emitter) scheduleLocked(key emitterKey, state *emitterState, now time.Time) {
	if state.pending == nil || state.scheduled || state.nextAttempt.After(now) {
		return
	}
	job := deliveryJob{key: key, report: *state.pending}
	select {
	case e.jobs <- job:
		state.scheduled = true
	default:
		state.nextAttempt = now.Add(e.config.RetryBase)
		e.stats.QueueFull++
	}
}

func (e *Emitter) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		select {
		case job := <-e.jobs:
			deliveryCtx, cancel := context.WithTimeout(ctx, e.config.ReportTimeout)
			err := e.config.Send(deliveryCtx, job.key.upSEID, job.report)
			cancel()
			result := deliveryResult{key: job.key, sequence: job.report.Sequence, err: err}
			// The result channel is sized for every queued and in-flight job, so
			// publishing cannot depend on the parent context remaining live. Run
			// drains these results after all workers stop during shutdown.
			e.results <- result
		case <-ctx.Done():
			return
		}
	}
}

func (e *Emitter) drainResults(now time.Time) {
	for {
		select {
		case result := <-e.results:
			e.complete(result, now)
		default:
			return
		}
	}
}

func (e *Emitter) complete(result deliveryResult, now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	state := e.states[result.key]
	if state == nil || state.pending == nil || state.pending.Sequence != result.sequence {
		return
	}
	state.scheduled = false
	if result.err == nil {
		state.pending = nil
		state.attempts = 0
		state.nextAttempt = time.Time{}
		e.stats.ReportsSent++
		return
	}
	state.attempts++
	state.nextAttempt = now.Add(retryDelay(e.config.RetryBase, e.config.RetryMax, state.attempts))
	e.stats.ReportsFailed++
	e.stats.ReportsRetried++
}

func makeIntervalReport(cpSEID uint64, sequence uint32, start time.Time, baseline, current Measurement, now time.Time) Report {
	end := canonicalUsageTime(current.LastPacket)
	if end.IsZero() {
		end = canonicalUsageTime(now)
	}
	start = canonicalUsageTime(start)
	if start.IsZero() || end.Before(start) {
		start = end
	}
	first := canonicalUsageTime(current.FirstPacket)
	if first.Before(start) || first.After(end) {
		first = time.Time{}
	}
	last := canonicalUsageTime(current.LastPacket)
	if last.Before(start) || last.After(end) {
		last = time.Time{}
	}
	return Report{
		CPSEID: cpSEID, URRID: current.URRID, Sequence: sequence,
		Trigger:         pfcpUsageVolumeThreshold,
		UplinkPackets:   current.UplinkPackets - baseline.UplinkPackets,
		DownlinkPackets: current.DownlinkPackets - baseline.DownlinkPackets,
		UplinkBytes:     current.UplinkBytes - baseline.UplinkBytes,
		DownlinkBytes:   current.DownlinkBytes - baseline.DownlinkBytes,
		StartTime:       start, EndTime: end, FirstPacket: first, LastPacket: last,
	}
}

// Kept local to avoid exposing quota-related trigger bits in the emitter.
const pfcpUsageVolumeThreshold uint32 = 1 << 1

func countersDecreased(current, baseline Measurement) bool {
	return current.UplinkPackets < baseline.UplinkPackets || current.DownlinkPackets < baseline.DownlinkPackets ||
		current.UplinkBytes < baseline.UplinkBytes || current.DownlinkBytes < baseline.DownlinkBytes ||
		current.ThresholdEvents < baseline.ThresholdEvents
}

func canonicalUsageTime(value time.Time) time.Time {
	if value.IsZero() {
		return time.Time{}
	}
	return value.UTC().Truncate(time.Second)
}

func retryDelay(base, maximum time.Duration, attempts int) time.Duration {
	delay := base
	for index := 1; index < attempts && delay < maximum; index++ {
		if delay > maximum/2 {
			return maximum
		}
		delay *= 2
	}
	if delay > maximum {
		return maximum
	}
	return delay
}
