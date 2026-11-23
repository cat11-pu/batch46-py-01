package task

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Errors reported by the handshake, authentication and forwarding calls.
var (
	ErrVersion  = errors.New("socks5: unsupported protocol version")
	ErrMethod   = errors.New("socks5: no acceptable authentication method")
	ErrAuth     = errors.New("socks5: authentication failed")
	ErrLocked   = errors.New("socks5: user temporarily locked")
	ErrState    = errors.New("socks5: operation not allowed in this state")
	ErrSession  = errors.New("socks5: unknown session")
	ErrCapacity = errors.New("socks5: session capacity reached")
	ErrQuota    = errors.New("socks5: per-user session quota reached")
	ErrPort     = errors.New("socks5: destination port not allowed")
	ErrAddress  = errors.New("socks5: destination address not allowed")
	ErrHost     = errors.New("socks5: host cannot be resolved")
	ErrBudget   = errors.New("socks5: session byte budget exceeded")
	ErrInvalid  = errors.New("socks5: invalid argument")
)

const (
	sessionNew           = "new"
	sessionGreeted       = "greeted"
	sessionAuthenticated = "authenticated"
	sessionConnected     = "connected"
	sessionClosed        = "closed"

	snapshotVersion = 1
	maxHostLength   = 255
)

// Config is the proxy policy.
type Config struct {
	// MaxSessions caps concurrently open sessions.
	MaxSessions int
	// MaxSessionsPerUser caps concurrently open sessions of one user.
	MaxSessionsPerUser int
	// IdleTimeout is how long a session may stay idle before it is swept.
	IdleTimeout time.Duration
	// MaxBytesPerSession caps the summed upload and download bytes.
	MaxBytesPerSession int64
	// AllowedPorts lists the destination ports that may be dialed.
	AllowedPorts []int
	// MaxAuthFailures is how many failed attempts lock a user.
	MaxAuthFailures int
	// LockoutDuration is how long a user stays locked.
	LockoutDuration time.Duration
}

// Greeting is the method negotiation sent by the client.
type Greeting struct {
	Version int
	Methods []byte
}

// Session is one proxy session.
type Session struct {
	ID         string
	User       string
	State      string
	Target     string
	BytesUp    int64
	BytesDown  int64
	OpenedAt   time.Time
	LastActive time.Time
}

// Target is the resolved destination of a CONNECT.
type Target struct {
	Host string
	IP   string
	Port int
}

// Stats reports proxy counters.
type Stats struct {
	Sessions  int
	Active    int
	BytesUp   int64
	BytesDown int64
	AuthFails int
}

type userRecord struct {
	tenantID   string
	proof      [sha256.Size]byte
	hasProof   bool
	failures   int
	lockedTill time.Time
}

type sessionRecord struct {
	session    Session
	state      string
	targetIP   string
	targetPort int
}

// Socks5Guard runs the SOCKS5 handshake, enforces authentication and per-user
// limits, and accounts for forwarded bytes.
type Socks5Guard struct {
	mu sync.Mutex

	cfg Config

	users    map[string]*userRecord
	sessions map[string]*sessionRecord

	resolver func(host string) ([]string, error)

	nextSessionID uint64
	totalSessions int
	active        int
	userActive    map[string]int
	bytesUp       int64
	bytesDown     int64
	authFails     int
}

// NewSocks5Guard returns a guard configured by cfg.
func NewSocks5Guard(cfg Config) *Socks5Guard {
	return &Socks5Guard{
		cfg:        cfg,
		users:      make(map[string]*userRecord),
		sessions:   make(map[string]*sessionRecord),
		userActive: make(map[string]int),
	}
}

type snapshotUser struct {
	Username   string `json:"username"`
	TenantID   string `json:"tenant_id"`
	Failures   int    `json:"failures"`
	LockedTill int64  `json:"locked_till"`
}

type snapshotSession struct {
	ID         string `json:"id"`
	User       string `json:"user,omitempty"`
	State      string `json:"state"`
	Target     string `json:"target,omitempty"`
	TargetIP   string `json:"target_ip,omitempty"`
	TargetPort int    `json:"target_port,omitempty"`
	BytesUp    int64  `json:"bytes_up"`
	BytesDown  int64  `json:"bytes_down"`
	OpenedAt   int64  `json:"opened_at"`
	LastActive int64  `json:"last_active"`
}

type snapshotCounters struct {
	Sessions  int   `json:"sessions"`
	BytesUp   int64 `json:"bytes_up"`
	BytesDown int64 `json:"bytes_down"`
	AuthFails int   `json:"auth_fails"`
}

type snapshotData struct {
	Version  int               `json:"version"`
	Users    []snapshotUser    `json:"users"`
	Sessions []snapshotSession `json:"sessions"`
	Counters snapshotCounters  `json:"counters"`
}

// NewSocks5GuardFromSnapshot restores a guard, including users, lockouts and
// byte counters, from a snapshot.
func NewSocks5GuardFromSnapshot(cfg Config, data []byte) (*Socks5Guard, error) {
	var snap snapshotData
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("%w: malformed snapshot", ErrInvalid)
	}
	if snap.Version != snapshotVersion {
		return nil, fmt.Errorf("%w: unsupported snapshot version", ErrInvalid)
	}
	if snap.Counters.Sessions < 0 || snap.Counters.BytesUp < 0 || snap.Counters.BytesDown < 0 || snap.Counters.AuthFails < 0 {
		return nil, fmt.Errorf("%w: negative snapshot counter", ErrInvalid)
	}

	g := NewSocks5Guard(cfg)
	g.totalSessions = snap.Counters.Sessions
	g.bytesUp = snap.Counters.BytesUp
	g.bytesDown = snap.Counters.BytesDown
	g.authFails = snap.Counters.AuthFails

	for _, u := range snap.Users {
		if u.Username == "" || u.TenantID == "" || u.Failures < 0 {
			return nil, fmt.Errorf("%w: invalid snapshot user", ErrInvalid)
		}
		if _, exists := g.users[u.Username]; exists {
			return nil, fmt.Errorf("%w: duplicate snapshot user", ErrInvalid)
		}
		rec := &userRecord{
			tenantID: u.TenantID,
			failures: u.Failures,
		}
		if u.LockedTill > 0 {
			rec.lockedTill = time.Unix(0, u.LockedTill)
		}
		g.users[u.Username] = rec
	}

	for _, s := range snap.Sessions {
		if s.ID == "" {
			return nil, fmt.Errorf("%w: invalid snapshot session", ErrInvalid)
		}
		if _, exists := g.sessions[s.ID]; exists {
			return nil, fmt.Errorf("%w: duplicate snapshot session", ErrInvalid)
		}
		if s.State != sessionNew && s.State != sessionGreeted && s.State != sessionAuthenticated && s.State != sessionConnected {
			return nil, fmt.Errorf("%w: invalid snapshot session state", ErrInvalid)
		}
		if s.BytesUp < 0 || s.BytesDown < 0 || s.OpenedAt < 0 || s.LastActive < 0 {
			return nil, fmt.Errorf("%w: invalid snapshot session counter", ErrInvalid)
		}
		if s.State == sessionAuthenticated || s.State == sessionConnected {
			if s.User == "" {
				return nil, fmt.Errorf("%w: snapshot session has no user", ErrInvalid)
			}
			if _, exists := g.users[s.User]; !exists {
				return nil, fmt.Errorf("%w: snapshot session references unknown user", ErrInvalid)
			}
			g.userActive[s.User]++
		} else if s.User != "" {
			return nil, fmt.Errorf("%w: unauthenticated snapshot session has a user", ErrInvalid)
		}
		g.sessions[s.ID] = &sessionRecord{
			session: Session{
				ID:         s.ID,
				User:       s.User,
				State:      s.State,
				Target:     s.Target,
				BytesUp:    s.BytesUp,
				BytesDown:  s.BytesDown,
				OpenedAt:   time.Unix(0, s.OpenedAt),
				LastActive: time.Unix(0, s.LastActive),
			},
			state:      s.State,
			targetIP:   s.TargetIP,
			targetPort: s.TargetPort,
		}
		g.active++
	}
	if g.totalSessions < g.active {
		return nil, fmt.Errorf("%w: snapshot session count is inconsistent", ErrInvalid)
	}

	return g, nil
}

// SetResolver installs the host resolver used by Connect. When it is not set,
// only literal IP addresses may be dialed.
func (g *Socks5Guard) SetResolver(fn func(host string) ([]string, error)) error {
	if fn == nil {
		return ErrInvalid
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.resolver = fn
	return nil
}

// AddUser registers a user with its authentication proof and tenant.
func (g *Socks5Guard) AddUser(username, proof, tenantID string) error {
	if username == "" || proof == "" || tenantID == "" || len(username) > maxHostLength {
		return ErrInvalid
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	rec := g.users[username]
	if rec == nil {
		rec = &userRecord{}
		g.users[username] = rec
	}
	rec.tenantID = tenantID
	rec.proof = sha256.Sum256([]byte(proof))
	rec.hasProof = true
	return nil
}

// Open allocates a new session in the "new" state.
func (g *Socks5Guard) Open(now time.Time) (Session, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.cfg.MaxSessions > 0 && g.active >= g.cfg.MaxSessions {
		return Session{}, ErrCapacity
	}

	g.nextSessionID++
	id := "s-" + strconv.FormatUint(g.nextSessionID, 10)
	rec := &sessionRecord{
		session: Session{
			ID:         id,
			State:      sessionNew,
			OpenedAt:   now,
			LastActive: now,
		},
		state: sessionNew,
	}
	g.sessions[id] = rec
	g.totalSessions++
	g.active++
	return rec.session, nil
}

// Greet negotiates the authentication method. Only username/password is
// acceptable; the no-authentication method is never selected.
func (g *Socks5Guard) Greet(sessionID string, gr Greeting, now time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	rec, ok := g.sessions[sessionID]
	if !ok {
		return ErrSession
	}
	if rec.state != sessionNew {
		return ErrState
	}
	if gr.Version != 5 {
		return ErrVersion
	}

	acceptable := false
	for _, method := range gr.Methods {
		if method == 0x02 {
			acceptable = true
			break
		}
	}
	if !acceptable {
		return ErrMethod
	}

	rec.state = sessionGreeted
	rec.session.State = sessionGreeted
	rec.session.LastActive = now
	return nil
}

// Authenticate verifies the username and proof of a greeted session and
// applies the lockout policy.
func (g *Socks5Guard) Authenticate(sessionID, username, proof string, now time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	rec, ok := g.sessions[sessionID]
	if !ok {
		return ErrSession
	}
	if rec.state != sessionGreeted {
		return ErrState
	}

	user, known := g.users[username]
	if known {
		if !user.lockedTill.IsZero() {
			if now.Before(user.lockedTill) {
				g.authFails++
				return ErrLocked
			}
			user.lockedTill = time.Time{}
			user.failures = 0
		}
	}

	proofHash := sha256.Sum256([]byte(proof))
	var stored [sha256.Size]byte
	if known && user.hasProof {
		stored = user.proof
	}
	valid := known && user.hasProof &&
		subtle.ConstantTimeCompare(proofHash[:], stored[:]) == 1

	if !valid {
		g.authFails++
		if known {
			user.failures++
			if g.cfg.MaxAuthFailures > 0 && user.failures >= g.cfg.MaxAuthFailures {
				user.lockedTill = now.Add(g.cfg.LockoutDuration)
			}
		}
		return ErrAuth
	}

	if g.cfg.MaxSessionsPerUser > 0 && g.userActive[username] >= g.cfg.MaxSessionsPerUser {
		return ErrQuota
	}

	user.failures = 0
	user.lockedTill = time.Time{}
	rec.state = sessionAuthenticated
	rec.session.State = sessionAuthenticated
	rec.session.User = username
	rec.session.LastActive = now
	g.userActive[username]++
	return nil
}

// Connect resolves and validates the destination of an authenticated session.
func (g *Socks5Guard) Connect(sessionID, host string, port int, now time.Time) (Target, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	rec, ok := g.sessions[sessionID]
	if !ok {
		return Target{}, ErrSession
	}
	if rec.state != sessionAuthenticated {
		return Target{}, ErrState
	}
	if port < 1 || port > 65535 {
		return Target{}, ErrInvalid
	}
	if !g.portAllowed(port) {
		return Target{}, ErrPort
	}
	if host == "" || len(host) > maxHostLength {
		return Target{}, ErrHost
	}

	ips, err := g.resolveHost(host)
	if err != nil || len(ips) == 0 {
		return Target{}, ErrHost
	}

	// Validate every answer, not merely the one selected, so a resolver cannot
	// smuggle an internal address into a multi-answer response.
	for _, ip := range ips {
		if !isPublicIP(ip) {
			return Target{}, ErrAddress
		}
	}

	chosen := ips[0].String()
	rec.state = sessionConnected
	rec.session.State = sessionConnected
	rec.session.Target = net.JoinHostPort(chosen, strconv.Itoa(port))
	rec.session.LastActive = now
	rec.targetIP = chosen
	rec.targetPort = port
	return Target{Host: host, IP: chosen, Port: port}, nil
}

func (g *Socks5Guard) portAllowed(port int) bool {
	if len(g.cfg.AllowedPorts) == 0 {
		return true
	}
	for _, allowed := range g.cfg.AllowedPorts {
		if allowed == port {
			return true
		}
	}
	return false
}

func (g *Socks5Guard) resolveHost(host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	if g.resolver == nil {
		return nil, ErrHost
	}
	answers, err := g.resolver(host)
	if err != nil || len(answers) == 0 {
		return nil, ErrHost
	}
	ips := make([]net.IP, 0, len(answers))
	for _, answer := range answers {
		ip := net.ParseIP(answer)
		if ip == nil {
			return nil, ErrHost
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

func isPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	// IPv4-mapped IPv6 addresses must be judged as IPv4.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsUnspecified() &&
		!ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() &&
		!ip.IsMulticast() && !ip.IsInterfaceLocalMulticast()
}

// Transfer accounts for forwarded bytes and enforces the per-session budget.
func (g *Socks5Guard) Transfer(sessionID string, up, down int64, now time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	rec, ok := g.sessions[sessionID]
	if !ok {
		return ErrSession
	}
	if rec.state != sessionConnected {
		return ErrState
	}
	if up < 0 || down < 0 {
		return ErrInvalid
	}

	total := rec.session.BytesUp + rec.session.BytesDown + up + down
	if g.cfg.MaxBytesPerSession > 0 && total > g.cfg.MaxBytesPerSession {
		g.closeLocked(sessionID)
		return ErrBudget
	}

	rec.session.BytesUp += up
	rec.session.BytesDown += down
	rec.session.LastActive = now
	g.bytesUp += up
	g.bytesDown += down
	return nil
}

// Close closes a session. Closing an already closed session is a no-op.
func (g *Socks5Guard) Close(sessionID string, now time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	rec, ok := g.sessions[sessionID]
	if !ok {
		return ErrSession
	}
	if rec.state == sessionClosed {
		return nil
	}
	g.closeLocked(sessionID)
	rec.session.LastActive = now
	return nil
}

func (g *Socks5Guard) closeLocked(sessionID string) {
	rec := g.sessions[sessionID]
	if rec == nil || rec.state == sessionClosed {
		return
	}
	if rec.state == sessionAuthenticated || rec.state == sessionConnected {
		if rec.session.User != "" {
			g.userActive[rec.session.User]--
			if g.userActive[rec.session.User] <= 0 {
				delete(g.userActive, rec.session.User)
			}
		}
	}
	rec.state = sessionClosed
	rec.session.State = sessionClosed
	if g.active > 0 {
		g.active--
	}
}

// Sweep closes sessions idle longer than IdleTimeout and returns how many
// were closed.
func (g *Socks5Guard) Sweep(now time.Time) int {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.cfg.IdleTimeout <= 0 {
		return 0
	}
	ids := make([]string, 0)
	for id, rec := range g.sessions {
		if rec.state == sessionClosed {
			continue
		}
		if now.Sub(rec.session.LastActive) > g.cfg.IdleTimeout {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		g.closeLocked(id)
	}
	return len(ids)
}

// Stats reports session and byte counters.
func (g *Socks5Guard) Stats() Stats {
	g.mu.Lock()
	defer g.mu.Unlock()
	return Stats{
		Sessions:  g.totalSessions,
		Active:    g.active,
		BytesUp:   g.bytesUp,
		BytesDown: g.bytesDown,
		AuthFails: g.authFails,
	}
}

// Snapshot serialises users, lockouts and counters.
func (g *Socks5Guard) Snapshot() ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	snap := snapshotData{
		Version: snapshotVersion,
		Counters: snapshotCounters{
			Sessions:  g.totalSessions,
			BytesUp:   g.bytesUp,
			BytesDown: g.bytesDown,
			AuthFails: g.authFails,
		},
	}
	for username, user := range g.users {
		su := snapshotUser{
			Username: username,
			TenantID: user.tenantID,
			Failures: user.failures,
		}
		if !user.lockedTill.IsZero() {
			su.LockedTill = user.lockedTill.UnixNano()
		}
		snap.Users = append(snap.Users, su)
	}
	sort.Slice(snap.Users, func(i, j int) bool {
		return snap.Users[i].Username < snap.Users[j].Username
	})

	for _, rec := range g.sessions {
		if rec.state == sessionClosed {
			continue
		}
		snap.Sessions = append(snap.Sessions, snapshotSession{
			ID:         rec.session.ID,
			User:       rec.session.User,
			State:      rec.state,
			Target:     rec.session.Target,
			TargetIP:   rec.targetIP,
			TargetPort: rec.targetPort,
			BytesUp:    rec.session.BytesUp,
			BytesDown:  rec.session.BytesDown,
			OpenedAt:   rec.session.OpenedAt.UnixNano(),
			LastActive: rec.session.LastActive.UnixNano(),
		})
	}
	sort.Slice(snap.Sessions, func(i, j int) bool {
		return snap.Sessions[i].ID < snap.Sessions[j].ID
	})

	return json.Marshal(snap)
}
