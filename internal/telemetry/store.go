package telemetry

import "sync"

type Store struct {
	mu       sync.RWMutex
	snapshot Snapshot
}

func NewStore(initial Snapshot) *Store {
	return &Store{snapshot: cloneSnapshot(initial)}
}

func (s *Store) Replace(snapshot Snapshot) {
	s.mu.Lock()
	s.snapshot = cloneSnapshot(snapshot)
	s.mu.Unlock()
}

func (s *Store) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneSnapshot(s.snapshot)
}

func cloneSnapshot(in Snapshot) Snapshot {
	out := in
	out.SGWC.Peers = append([]Peer(nil), in.SGWC.Peers...)
	out.SGWC.Procedures = append([]Procedure(nil), in.SGWC.Procedures...)
	out.SGWU.QCI = append([]QCIUsage(nil), in.SGWU.QCI...)
	out.History = append([]TrafficPoint(nil), in.History...)
	out.Events = make([]Event, len(in.Events))
	for i, event := range in.Events {
		out.Events[i] = event
		if event.Context != nil {
			out.Events[i].Context = make(map[string]string, len(event.Context))
			for key, value := range event.Context {
				out.Events[i].Context[key] = value
			}
		}
	}
	return out
}
