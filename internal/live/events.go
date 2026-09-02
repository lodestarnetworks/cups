// Package live turns running SGW-C and SGW-U state into management telemetry.
package live

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lodestarnetworks/cups/internal/sgwc/gateway"
	"github.com/lodestarnetworks/cups/internal/telemetry"
)

type EventLog struct {
	mu     sync.RWMutex
	nextID atomic.Uint64
	limit  int
	events []telemetry.Event
}

func NewEventLog(limit int) *EventLog {
	if limit <= 0 {
		limit = 200
	}
	return &EventLog{limit: limit}
}

func (l *EventLog) Add(component string, severity telemetry.Severity, kind, summary string, context map[string]string) {
	event := telemetry.Event{
		ID: l.nextID.Add(1), At: time.Now().UTC(), Component: component,
		Severity: severity, Kind: kind, Summary: summary, Context: cloneContext(context),
	}
	l.mu.Lock()
	l.events = append([]telemetry.Event{event}, l.events...)
	if len(l.events) > l.limit {
		l.events = l.events[:l.limit]
	}
	l.mu.Unlock()
}

func (l *EventLog) GatewaySink(event gateway.Event) {
	severity := telemetry.SeverityInfo
	switch event.Severity {
	case "warning":
		severity = telemetry.SeverityWarning
	case "error":
		severity = telemetry.SeverityError
	}
	context := map[string]string{}
	if event.Peer.Addr().IsValid() {
		context["peer"] = event.Peer.String()
	}
	if event.Subscriber != "" {
		context["subscriber"] = event.Subscriber
	}
	l.Add("sgw-c", severity, event.Procedure, event.Message, context)
}

func (l *EventLog) Snapshot() []telemetry.Event {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]telemetry.Event, len(l.events))
	for index, event := range l.events {
		out[index] = event
		out[index].Context = cloneContext(event.Context)
	}
	return out
}

func cloneContext(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func startupContext(values ...any) map[string]string {
	out := make(map[string]string, len(values)/2)
	for index := 0; index+1 < len(values); index += 2 {
		out[fmt.Sprint(values[index])] = fmt.Sprint(values[index+1])
	}
	return out
}
