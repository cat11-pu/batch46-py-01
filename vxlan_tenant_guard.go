package task

import (
	"errors"
	"time"
)

// Sentinel errors describing why a tenant isolation decision was refused.
var (
	ErrVNIRange      = errors.New("vxlan: vni outside the usable range")
	ErrVNIBound      = errors.New("vxlan: vni already owned by another tenant")
	ErrTenantUnknown = errors.New("vxlan: vni is not bound to a tenant")
	ErrMACConflict   = errors.New("vxlan: mac address belongs to another tenant or vni")
	ErrMACLimit      = errors.New("vxlan: per tenant mac limit reached")
	ErrNotFound      = errors.New("vxlan: entry not found or expired")
)

var errNotImplemented = errors.New("not implemented")

// Config controls learning and capacity.
//
// MaxMACsPerTenant bounds the number of live MAC entries one tenant may hold.
// LearnTTL is the sliding lifetime of a learned entry.
type Config struct {
	MaxMACsPerTenant int
	LearnTTL         time.Duration
}

// Frame is the inner Ethernet frame carried by a VXLAN packet.
type Frame struct {
	VNI    int
	SrcMAC string
	DstMAC string
	SrcIP  string
}

// Entry is one learned inner MAC address.
type Entry struct {
	MAC       string
	VNI       int
	TenantID  string
	SrcIP     string
	LearnedAt time.Time
}

// Stats counts learning outcomes.
type Stats struct {
	Learned  int
	Rejected int
	Evicted  int
}

// VxlanGuard enforces that a VNI belongs to exactly one tenant and that inner
// source addresses never cross the tenant boundary.
type VxlanGuard struct {
	cfg Config
}

// NewVxlanGuard returns a guard configured by cfg.
func NewVxlanGuard(cfg Config) *VxlanGuard {
	return &VxlanGuard{cfg: cfg}
}

// NewVxlanGuardFromSnapshot restores bindings and learned entries from data.
func NewVxlanGuardFromSnapshot(cfg Config, data []byte) (*VxlanGuard, error) {
	return nil, errNotImplemented
}

// BindVNI assigns vni to tenantID. The usable range excludes the reserved VNIs
// 0 and 16777215. Rebinding to the same tenant is a no-op.
func (g *VxlanGuard) BindVNI(vni int, tenantID string) error {
	return errNotImplemented
}

// UnbindVNI removes the binding and every entry learned on vni, returning how
// many entries were dropped.
func (g *VxlanGuard) UnbindVNI(vni int) (int, error) {
	return 0, errNotImplemented
}

// TenantForVNI returns the tenant that owns vni.
func (g *VxlanGuard) TenantForVNI(vni int) (string, error) {
	return "", errNotImplemented
}

// Learn records the inner source MAC of a frame.
//
// A MAC may be learned only on a VNI bound to the tenant that already owns it;
// moving it to another tenant or another VNI of the same tenant is refused.
// Re-learning the same MAC on its current VNI refreshes the entry.
func (g *VxlanGuard) Learn(frame Frame, now time.Time) error {
	return errNotImplemented
}

// Lookup returns the live entry for mac on vni. Entries at or past LearnTTL
// are treated as absent.
func (g *VxlanGuard) Lookup(vni int, mac string, now time.Time) (Entry, error) {
	return Entry{}, errNotImplemented
}

// Expire drops every entry at or past its TTL and returns the number dropped.
func (g *VxlanGuard) Expire(now time.Time) int {
	return 0
}

// TenantMACCount reports how many entries are stored for tenantID.
func (g *VxlanGuard) TenantMACCount(tenantID string) int {
	return 0
}

// Snapshot serialises VNI bindings and learned entries.
func (g *VxlanGuard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}

// Stats returns the learning counters.
func (g *VxlanGuard) Stats() Stats {
	return Stats{}
}
