package task

import (
	"errors"
	"time"
)

var errNotImplemented = errors.New("not implemented")

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

// MqttSessionGuard tracks MQTT sessions, offline queues, in-flight packet ids
// and delayed wills.
type MqttSessionGuard struct {
	cfg Config
}

// NewMqttSessionGuard returns an empty guard governed by cfg.
func NewMqttSessionGuard(cfg Config) *MqttSessionGuard {
	return &MqttSessionGuard{cfg: cfg}
}

// NewMqttSessionGuardFromSnapshot restores sessions, queues and pending wills
// from data produced by Snapshot.
func NewMqttSessionGuardFromSnapshot(cfg Config, data []byte) (*MqttSessionGuard, error) {
	return nil, errNotImplemented
}

// Connect starts or resumes a session, reporting whether a live connection
// was taken over.
func (g *MqttSessionGuard) Connect(clientID string, cleanStart bool, will Will, now time.Time) (Takeover, error) {
	return Takeover{}, errNotImplemented
}

// Disconnect closes a connection gracefully and never publishes the will.
func (g *MqttSessionGuard) Disconnect(clientID string, clean bool, now time.Time) error {
	return errNotImplemented
}

// Lose marks a connection as dropped without a DISCONNECT packet and
// schedules its will.
func (g *MqttSessionGuard) Lose(clientID string, now time.Time) error {
	return errNotImplemented
}

// Queue appends a message to the session's offline queue.
func (g *MqttSessionGuard) Queue(clientID string, msg Message, now time.Time) error {
	return errNotImplemented
}

// Pending returns a copy of the queued messages in FIFO order.
func (g *MqttSessionGuard) Pending(clientID string) ([]Message, error) {
	return nil, errNotImplemented
}

// Next moves the head of the queue in flight and returns it.
func (g *MqttSessionGuard) Next(clientID string, now time.Time) (Message, error) {
	return Message{}, errNotImplemented
}

// Ack acknowledges an in-flight packet id.
func (g *MqttSessionGuard) Ack(clientID string, packetID uint16) error {
	return errNotImplemented
}

// Inflight returns the number of unacknowledged messages of a session.
func (g *MqttSessionGuard) Inflight(clientID string) (int, error) {
	return 0, errNotImplemented
}

// Subscribe adds a subscription; duplicates are ignored.
func (g *MqttSessionGuard) Subscribe(clientID, topic string) error {
	return errNotImplemented
}

// Subscriptions returns the session's topics in lexical order.
func (g *MqttSessionGuard) Subscriptions(clientID string) ([]string, error) {
	return nil, errNotImplemented
}

// DueWills returns and clears the wills whose due time has been reached.
func (g *MqttSessionGuard) DueWills(now time.Time) []Will {
	return nil
}

// PurgeExpired removes disconnected sessions past their expiry and returns
// how many were dropped.
func (g *MqttSessionGuard) PurgeExpired(now time.Time) int {
	return 0
}

// SessionCount returns the number of tracked sessions.
func (g *MqttSessionGuard) SessionCount() int {
	return 0
}

// Info returns the public view of one session.
func (g *MqttSessionGuard) Info(clientID string) (SessionInfo, error) {
	return SessionInfo{}, errNotImplemented
}

// Stats returns the current counters.
func (g *MqttSessionGuard) Stats() Stats {
	return Stats{}
}

// Snapshot serialises sessions, queues and pending wills.
func (g *MqttSessionGuard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}
