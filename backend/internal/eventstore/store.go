// Package eventstore holds the last N parsed events from events.jsonl in memory
// and exposes query and aggregation helpers used by the API handlers.
package eventstore

import (
	"encoding/json"
	"sync"
)

const defaultCap = 5000

// Event is the parsed representation of one line from events.jsonl.
// Fields map exactly to what qks_daemon writes.
type Event struct {
	TsDaemon string          `json:"ts_daemon"`
	EventID  uint64          `json:"event_id"`
	Type     string          `json:"type"`
	Policy   string          `json:"policy"`
	Reason   string          `json:"reason"`
	MlProb   *float64        `json:"ml_prob,omitempty"`
	Sig      *SigBlock       `json:"sig,omitempty"`
	Exec     *ExecBlock      `json:"exec,omitempty"`
	Packet   *PacketBlock    `json:"packet,omitempty"`
	PacketIn *PacketBlock    `json:"packet_in,omitempty"`
	DNS      *DNSBlock       `json:"dns,omitempty"`
	Syscall  *SyscallBlock   `json:"syscall,omitempty"`
	Raw      json.RawMessage `json:"-"`
}

type SigBlock struct {
	Status string `json:"status"`
	Len    int    `json:"len"`
	Scheme string `json:"scheme"`
	Hash   string `json:"hash"`
}

type ExecBlock struct {
	PID  uint32 `json:"pid"`
	PPID uint32 `json:"ppid"`
	UID  uint32 `json:"uid"`
	Path string `json:"path"`
}

type PacketBlock struct {
	PID      uint32 `json:"pid,omitempty"`
	UID      uint32 `json:"uid,omitempty"`
	ExecPath string `json:"exec_path,omitempty"`
	SrcIP    string `json:"src_ip"`
	SrcPort  uint16 `json:"src_port"`
	DstIP    string `json:"dst_ip"`
	DstPort  uint16 `json:"dst_port"`
	Protocol uint8  `json:"protocol"`
	TCPFlags string `json:"tcp_flags,omitempty"`
	Len      uint16 `json:"len"`
}

type DNSBlock struct {
	PID      uint32 `json:"pid"`
	UID      uint32 `json:"uid"`
	ExecPath string `json:"exec_path"`
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	QName    string `json:"qname"`
	QType    uint16 `json:"qtype"`
}

type SyscallBlock struct {
	PID               uint32 `json:"pid"`
	PPID              uint32 `json:"ppid"`
	UID               uint32 `json:"uid"`
	ExecPath          string `json:"exec_path"`
	NR                uint32 `json:"nr"`
	Subtype           uint32 `json:"subtype"`
	Flags             string `json:"flags"`
	Prot              string `json:"prot"`
	Arg0              uint32 `json:"arg0"`
	Arg1              uint32 `json:"arg1"`
	Arg2              uint32 `json:"arg2"`
	ArgStr            string `json:"arg_str"`
	SockDomain        uint32 `json:"sock_domain"`
	SockType          uint32 `json:"sock_type"`
	SockTypeWithFlags uint32 `json:"sock_type_with_flags"`
	SockProtocol      uint32 `json:"sock_protocol"`
}

// Store is a thread-safe fixed-capacity ring buffer of Events.
type Store struct {
	mu    sync.RWMutex
	ring  []*Event
	cap   int
	head  int // index of the oldest slot
	count int // number of valid entries (≤ cap)

	// running totals for fast metrics
	totalAllow int
	totalDeny  int
	totalML    int // events where ml_prob was set
}

// New creates a Store with the given capacity (defaults to defaultCap if 0).
func New(capacity int) *Store {
	if capacity <= 0 {
		capacity = defaultCap
	}
	return &Store{
		ring: make([]*Event, capacity),
		cap:  capacity,
	}
}

// Push adds a new event. If the buffer is full the oldest entry is evicted.
func (s *Store) Push(ev *Event) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// evict the slot we're about to overwrite
	if s.count == s.cap {
		old := s.ring[s.head]
		if old != nil {
			s.subtractTotals(old)
		}
		s.head = (s.head + 1) % s.cap
	} else {
		s.count++
	}

	slot := (s.head + s.count - 1) % s.cap
	s.ring[slot] = ev
	s.addTotals(ev)
}

func (s *Store) addTotals(ev *Event) {
	switch ev.Policy {
	case "ALLOW":
		s.totalAllow++
	case "DENY":
		s.totalDeny++
	}
	if ev.MlProb != nil {
		s.totalML++
	}
}

func (s *Store) subtractTotals(ev *Event) {
	switch ev.Policy {
	case "ALLOW":
		s.totalAllow--
	case "DENY":
		s.totalDeny--
	}
	if ev.MlProb != nil {
		s.totalML--
	}
}

// QueryOptions filters for the Events method.
type QueryOptions struct {
	Limit     int    // 0 = use default (50)
	EventType string // "EXEC", "PACKET", etc. — empty = all
	Policy    string // "ALLOW" or "DENY"      — empty = all
	SinceID   uint64 // return only events with EventID > SinceID
}

// Events returns events in newest-first order, filtered by opts.
func (s *Store) Events(opts QueryOptions) []*Event {
	if opts.Limit <= 0 {
		opts.Limit = 50
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*Event, 0, opts.Limit)

	// Iterate newest → oldest
	for i := 0; i < s.count && len(result) < opts.Limit; i++ {
		idx := (s.head + s.count - 1 - i) % s.cap
		ev := s.ring[idx]
		if ev == nil {
			continue
		}
		if opts.SinceID > 0 && ev.EventID <= opts.SinceID {
			continue
		}
		if opts.EventType != "" && ev.Type != opts.EventType {
			continue
		}
		if opts.Policy != "" && ev.Policy != opts.Policy {
			continue
		}
		result = append(result, ev)
	}

	return result
}

// Totals returns snapshot counters without iterating.
type Totals struct {
	Total      int
	TotalAllow int
	TotalDeny  int
	TotalML    int
}

func (s *Store) Totals() Totals {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Totals{
		Total:      s.count,
		TotalAllow: s.totalAllow,
		TotalDeny:  s.totalDeny,
		TotalML:    s.totalML,
	}
}

// ParseLine parses a single JSON line from events.jsonl into an Event.
func ParseLine(line []byte) (*Event, error) {
	var ev Event
	if err := json.Unmarshal(line, &ev); err != nil {
		return nil, err
	}
	ev.Raw = line
	return &ev, nil
}
