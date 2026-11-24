package task

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Sentinel errors returned by MqttSessionGuard.
var (
	// ErrSessionAbsent means no live session exists for the client id.
	ErrSessionAbsent = errors.New("mqtt: session not found")
	// ErrQueueFull means the offline queue reached MaxQueued.
	ErrQueueFull = errors.New("mqtt: offline queue limit reached")
	// ErrQueueEmpty means there is no queued message to deliver.
	ErrQueueEmpty = errors.New("mqtt: offline queue is empty")
	// ErrDuplicatePacketID means the packet id is queued or in flight.
	ErrDuplicatePacketID = errors.New("mqtt: packet id already in use")
	// ErrInflightLimit means MaxInflight messages are already unacknowledged.
	ErrInflightLimit = errors.New("mqtt: in-flight limit reached")
	// ErrUnknownPacketID means the packet id is not in flight.
	ErrUnknownPacketID = errors.New("mqtt: unknown packet id")
	// ErrCorruptSnapshot means a snapshot could not be decoded.
	ErrCorruptSnapshot = errors.New("mqtt: corrupt snapshot")
	// ErrSnapshotVersion means the snapshot was produced by an incompatible
	// implementation.
	ErrSnapshotVersion = fmt.Errorf("mqtt: unsupported snapshot version: %w", ErrCorruptSnapshot)
)

// Config holds session policy.
type Config struct {
	// MaxQueued is the offline queue limit per session.
	MaxQueued int
	// SessionExpiry is how long a disconnected session is kept.
	SessionExpiry time.Duration
	// WillDelay is the default will delay when the will carries none.
	WillDelay time.Duration
	// MaxInflight is the unacknowledged message limit per session.
	MaxInflight int
}

// Will is the last message a connection asks the broker to publish when it
// disappears.
type Will struct {
	Topic   string
	Payload string
	QoS     byte
	Delay   time.Duration
}

// Message is one application message.
type Message struct {
	Topic    string
	Payload  string
	QoS      byte
	PacketID uint16
}

// Takeover reports what happened to a previous connection of the same client
// id.
type Takeover struct {
	ClientID string
	Replaced bool
}

// SessionInfo is the public view of one session.
type SessionInfo struct {
	ClientID      string
	Connected     bool
	ExpiresAt     time.Time
	Queued        int
	Inflight      int
	Subscriptions []string
}

// Stats is a counter snapshot.
type Stats struct {
	Sessions     int
	Queued       int
	Inflight     int
	WillsPending int
	Takeovers    uint64
}

type session struct {
	clientID      string
	connected     bool
	expiresAt     time.Time
	queue         []Message
	inflight      map[uint16]Message
	subscriptions map[string]struct{}
	will          Will
}

type pendingWill struct {
	ClientID string    `json:"client_id"`
	Will     Will      `json:"will"`
	DueAt    time.Time `json:"due_at"`
}

// MqttSessionGuard tracks MQTT sessions, offline queues, in-flight packet ids
// and delayed wills.
type MqttSessionGuard struct {
	mu        sync.Mutex
	cfg       Config
	sessions  map[string]*session
	wills     []pendingWill
	takeovers uint64
}

// NewMqttSessionGuard returns an empty guard governed by cfg.
func NewMqttSessionGuard(cfg Config) *MqttSessionGuard {
	return &MqttSessionGuard{
		cfg:      cfg,
		sessions: make(map[string]*session),
	}
}

// NewMqttSessionGuardFromSnapshot restores sessions, queues and pending wills
// from data produced by Snapshot.
func NewMqttSessionGuardFromSnapshot(cfg Config, data []byte) (*MqttSessionGuard, error) {
	var state snapshotState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, ErrCorruptSnapshot
	}
	if state.Version != snapshotVersion {
		return nil, ErrSnapshotVersion
	}

	g := NewMqttSessionGuard(cfg)
	for _, snap := range state.Sessions {
		if snap.ClientID == "" {
			return nil, ErrCorruptSnapshot
		}
		if _, exists := g.sessions[snap.ClientID]; exists {
			return nil, ErrCorruptSnapshot
		}
		s := &session{
			clientID:      snap.ClientID,
			connected:     snap.Connected,
			expiresAt:     snap.ExpiresAt,
			queue:         append([]Message(nil), snap.Queue...),
			inflight:      make(map[uint16]Message, len(snap.Inflight)),
			subscriptions: make(map[string]struct{}, len(snap.Subscriptions)),
			will:          snap.Will,
		}
		for _, item := range snap.Inflight {
			if _, exists := s.inflight[item.PacketID]; exists {
				return nil, ErrCorruptSnapshot
			}
			if item.PacketID != item.Message.PacketID {
				return nil, ErrCorruptSnapshot
			}
			s.inflight[item.PacketID] = item.Message
		}
		for _, sub := range snap.Subscriptions {
			s.subscriptions[sub] = struct{}{}
		}
		g.sessions[snap.ClientID] = s
	}
	g.wills = append(g.wills, state.Wills...)
	g.takeovers = state.Takeovers
	return g, nil
}

// Connect starts or resumes a session, reporting whether a live connection
// was taken over.
func (g *MqttSessionGuard) Connect(clientID string, cleanStart bool, will Will, now time.Time) (Takeover, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	s := g.sessions[clientID]
	if s != nil && !s.connected && !s.expiresAt.IsZero() && !now.Before(s.expiresAt) {
		delete(g.sessions, clientID)
		s = nil
	}

	replaced := false
	if s == nil {
		s = &session{
			clientID:      clientID,
			inflight:      make(map[uint16]Message),
			subscriptions: make(map[string]struct{}),
		}
		g.sessions[clientID] = s
		g.removeWillsLocked(clientID)
	} else if s.connected {
		replaced = true
		g.takeovers++
		g.scheduleWillLocked(clientID, s.will, now, true)
		s.inflight = make(map[uint16]Message)
	} else {
		// A connection that resumes before its delayed will is due cancels
		// the will instead of publishing it.
		g.removeWillsLocked(clientID)
	}

	if cleanStart {
		s.queue = nil
		s.inflight = make(map[uint16]Message)
		s.subscriptions = make(map[string]struct{})
	}
	s.connected = true
	s.expiresAt = time.Time{}
	s.will = will

	return Takeover{ClientID: clientID, Replaced: replaced}, nil
}

// Disconnect closes a connection gracefully and never publishes the will.
func (g *MqttSessionGuard) Disconnect(clientID string, clean bool, now time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	s := g.sessions[clientID]
	if s == nil {
		return ErrSessionAbsent
	}

	g.removeWillsLocked(clientID)
	if clean {
		delete(g.sessions, clientID)
		return nil
	}

	s.connected = false
	s.expiresAt = now.Add(g.cfg.SessionExpiry)
	s.will = Will{}
	return nil
}

// Lose marks a connection as dropped without a DISCONNECT packet and
// schedules its will.
func (g *MqttSessionGuard) Lose(clientID string, now time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	s := g.sessions[clientID]
	if s == nil || (!s.connected && !s.expiresAt.IsZero() && !now.Before(s.expiresAt)) {
		if s != nil {
			delete(g.sessions, clientID)
		}
		return ErrSessionAbsent
	}
	if !s.connected {
		return nil
	}

	s.connected = false
	s.expiresAt = now.Add(g.cfg.SessionExpiry)
	g.scheduleWillLocked(clientID, s.will, now, false)
	return nil
}

// Queue appends a message to the session's offline queue.
func (g *MqttSessionGuard) Queue(clientID string, msg Message, now time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	s := g.sessionForNowLocked(clientID, now)
	if s == nil {
		return ErrSessionAbsent
	}
	if s.hasPacketID(msg.PacketID) {
		return ErrDuplicatePacketID
	}
	if g.cfg.MaxQueued <= 0 || len(s.queue) >= g.cfg.MaxQueued {
		return ErrQueueFull
	}
	s.queue = append(s.queue, msg)
	return nil
}

// Pending returns a copy of the queued messages in FIFO order.
func (g *MqttSessionGuard) Pending(clientID string) ([]Message, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	s := g.sessions[clientID]
	if s == nil {
		return nil, ErrSessionAbsent
	}
	out := make([]Message, len(s.queue))
	copy(out, s.queue)
	return out, nil
}

// Next moves the head of the queue in flight and returns it.
func (g *MqttSessionGuard) Next(clientID string, now time.Time) (Message, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	s := g.sessionForNowLocked(clientID, now)
	if s == nil {
		return Message{}, ErrSessionAbsent
	}
	if len(s.queue) == 0 {
		return Message{}, ErrQueueEmpty
	}
	if g.cfg.MaxInflight <= 0 || len(s.inflight) >= g.cfg.MaxInflight {
		return Message{}, ErrInflightLimit
	}

	msg := s.queue[0]
	s.queue = s.queue[1:]
	s.inflight[msg.PacketID] = msg
	return msg, nil
}

// Ack acknowledges an in-flight packet id.
func (g *MqttSessionGuard) Ack(clientID string, packetID uint16) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	s := g.sessions[clientID]
	if s == nil {
		return ErrSessionAbsent
	}
	if _, ok := s.inflight[packetID]; !ok {
		return ErrUnknownPacketID
	}
	delete(s.inflight, packetID)
	return nil
}

// Inflight returns the number of unacknowledged messages of a session.
func (g *MqttSessionGuard) Inflight(clientID string) (int, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	s := g.sessions[clientID]
	if s == nil {
		return 0, ErrSessionAbsent
	}
	return len(s.inflight), nil
}

// Subscribe adds a subscription; duplicates are ignored.
func (g *MqttSessionGuard) Subscribe(clientID, topic string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	s := g.sessions[clientID]
	if s == nil {
		return ErrSessionAbsent
	}
	s.subscriptions[topic] = struct{}{}
	return nil
}

// Subscriptions returns the session's topics in lexical order.
func (g *MqttSessionGuard) Subscriptions(clientID string) ([]string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	s := g.sessions[clientID]
	if s == nil {
		return nil, ErrSessionAbsent
	}
	return s.subscriptionList(), nil
}

// DueWills returns and clears the wills whose due time has been reached.
func (g *MqttSessionGuard) DueWills(now time.Time) []Will {
	g.mu.Lock()
	defer g.mu.Unlock()

	return g.takeDueWillsLocked(now)
}

// PurgeExpired removes disconnected sessions past their expiry and returns
// how many were dropped.
func (g *MqttSessionGuard) PurgeExpired(now time.Time) int {
	g.mu.Lock()
	defer g.mu.Unlock()

	dropped := 0
	for clientID, s := range g.sessions {
		if s.connected || s.expiresAt.IsZero() || now.Before(s.expiresAt) {
			continue
		}
		delete(g.sessions, clientID)
		dropped++
	}
	return dropped
}

// SessionCount returns the number of tracked sessions.
func (g *MqttSessionGuard) SessionCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.sessions)
}

// Info returns the public view of one session.
func (g *MqttSessionGuard) Info(clientID string) (SessionInfo, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	s := g.sessions[clientID]
	if s == nil {
		return SessionInfo{}, ErrSessionAbsent
	}
	return SessionInfo{
		ClientID:      clientID,
		Connected:     s.connected,
		ExpiresAt:     s.expiresAt,
		Queued:        len(s.queue),
		Inflight:      len(s.inflight),
		Subscriptions: s.subscriptionList(),
	}, nil
}

// Stats returns the current counters.
func (g *MqttSessionGuard) Stats() Stats {
	g.mu.Lock()
	defer g.mu.Unlock()

	stats := Stats{
		Sessions:     len(g.sessions),
		WillsPending: len(g.wills),
		Takeovers:    g.takeovers,
	}
	for _, s := range g.sessions {
		stats.Queued += len(s.queue)
		stats.Inflight += len(s.inflight)
	}
	return stats
}

const snapshotVersion = 1

type snapshotState struct {
	Version   int               `json:"version"`
	Sessions  []snapshotSession `json:"sessions"`
	Wills     []pendingWill     `json:"wills"`
	Takeovers uint64            `json:"takeovers"`
}

type snapshotSession struct {
	ClientID      string             `json:"client_id"`
	Connected     bool               `json:"connected"`
	ExpiresAt     time.Time          `json:"expires_at"`
	Queue         []Message          `json:"queue"`
	Inflight      []snapshotInflight `json:"inflight"`
	Subscriptions []string           `json:"subscriptions"`
	Will          Will               `json:"will"`
}

type snapshotInflight struct {
	PacketID uint16  `json:"packet_id"`
	Message  Message `json:"message"`
}

// Snapshot serialises sessions, queues and pending wills.
func (g *MqttSessionGuard) Snapshot() ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	state := snapshotState{
		Version:   snapshotVersion,
		Wills:     append([]pendingWill(nil), g.wills...),
		Takeovers: g.takeovers,
	}
	ids := make([]string, 0, len(g.sessions))
	for clientID := range g.sessions {
		ids = append(ids, clientID)
	}
	sort.Strings(ids)
	for _, clientID := range ids {
		s := g.sessions[clientID]
		snap := snapshotSession{
			ClientID:      s.clientID,
			Connected:     s.connected,
			ExpiresAt:     s.expiresAt,
			Queue:         append([]Message(nil), s.queue...),
			Subscriptions: s.subscriptionList(),
			Will:          s.will,
		}
		packetIDs := make([]int, 0, len(s.inflight))
		for packetID := range s.inflight {
			packetIDs = append(packetIDs, int(packetID))
		}
		sort.Ints(packetIDs)
		for _, packetID := range packetIDs {
			id := uint16(packetID)
			snap.Inflight = append(snap.Inflight, snapshotInflight{
				PacketID: id,
				Message:  s.inflight[id],
			})
		}
		state.Sessions = append(state.Sessions, snap)
	}
	return json.Marshal(state)
}

func (s *session) hasPacketID(packetID uint16) bool {
	if _, ok := s.inflight[packetID]; ok {
		return true
	}
	for _, msg := range s.queue {
		if msg.PacketID == packetID {
			return true
		}
	}
	return false
}

func (s *session) subscriptionList() []string {
	out := make([]string, 0, len(s.subscriptions))
	for topic := range s.subscriptions {
		out = append(out, topic)
	}
	sort.Strings(out)
	return out
}

func (g *MqttSessionGuard) sessionForNowLocked(clientID string, now time.Time) *session {
	s := g.sessions[clientID]
	if s == nil {
		return nil
	}
	if !s.connected && !s.expiresAt.IsZero() && !now.Before(s.expiresAt) {
		delete(g.sessions, clientID)
		return nil
	}
	return s
}

func (g *MqttSessionGuard) scheduleWillLocked(clientID string, will Will, now time.Time, immediate bool) {
	if will.Topic == "" {
		return
	}
	delay := will.Delay
	if delay <= 0 {
		delay = g.cfg.WillDelay
	}
	if immediate {
		delay = 0
	}
	g.wills = append(g.wills, pendingWill{
		ClientID: clientID,
		Will:     will,
		DueAt:    now.Add(delay),
	})
}

func (g *MqttSessionGuard) removeWillsLocked(clientID string) {
	if len(g.wills) == 0 {
		return
	}
	out := g.wills[:0]
	for _, pending := range g.wills {
		if pending.ClientID != clientID {
			out = append(out, pending)
		}
	}
	g.wills = out
}

func (g *MqttSessionGuard) takeDueWillsLocked(now time.Time) []Will {
	if len(g.wills) == 0 {
		return nil
	}
	var due []Will
	out := g.wills[:0]
	for _, pending := range g.wills {
		if !now.Before(pending.DueAt) {
			due = append(due, pending.Will)
			continue
		}
		out = append(out, pending)
	}
	g.wills = out
	return due
}
