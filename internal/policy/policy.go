// Package policy holds the machine policy an administrator may set for the
// Hifaz service, and the checks the service makes with it before it applies
// a tunnel configuration.
//
// With no policy set, any Hifaz server may be used and full tunnels are
// refused. The Windows registry location is in policy_windows.go.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/protocol"
)

// Policy is the machine policy.
type Policy struct {
	// AllowFullTunnel lets a server route all IPv4 or all IPv6 traffic
	// through the tunnel. Off by default.
	AllowFullTunnel bool
	// Servers, when not empty, are the only servers users may enroll with
	// and connect to.
	Servers []Server
}

// Server is one allowed server: its public URL and, optionally, the
// fingerprint it must have.
type Server struct {
	URL         string
	Fingerprint protocol.Fingerprint
}

// ParseServer parses a policy entry: "<public URL>" or
// "<public URL> <fingerprint>".
func ParseServer(entry string) (Server, error) {
	fields := strings.Fields(entry)
	if len(fields) == 0 || len(fields) > 2 {
		return Server{}, fmt.Errorf("invalid server entry %q", entry)
	}
	u, err := protocol.NormalizeServerURL(fields[0])
	if err != nil {
		return Server{}, fmt.Errorf("server entry %q: %w", entry, err)
	}
	s := Server{URL: u}
	if len(fields) == 2 {
		if s.Fingerprint, err = protocol.ParseFingerprint(fields[1]); err != nil {
			return Server{}, fmt.Errorf("server entry %q: %w", entry, err)
		}
	}
	return s, nil
}

// Error codes of policy refusals, shown to the user by the app.
var (
	ErrServerNotAllowed = errors.New("this server is not allowed on this computer")
	ErrFullTunnel       = errors.New("this server sends all traffic through the tunnel, which is not allowed on this computer")
)

// AllowsServer reports whether server (a normalized URL) with fingerprint fp
// may be used.
func (p Policy) AllowsServer(server string, fp protocol.Fingerprint) error {
	if len(p.Servers) == 0 {
		return nil
	}
	for _, s := range p.Servers {
		if s.URL == server && (s.Fingerprint == "" || s.Fingerprint == fp) {
			return nil
		}
	}
	return ErrServerNotAllowed
}

// CheckConfig checks a tunnel configuration against the policy.
func (p Policy) CheckConfig(cfg *protocol.TunnelConfig) error {
	if p.AllowFullTunnel {
		return nil
	}
	if v4, v6 := FullTunnel(cfg.AllowedIPs); v4 || v6 {
		return ErrFullTunnel
	}
	return nil
}

// FullTunnel reports whether the ranges together cover the whole IPv4 or
// the whole IPv6 address space, however they are split (0.0.0.0/0, or
// 0.0.0.0/1 with 128.0.0.0/1, and so on).
func FullTunnel(prefixes []netip.Prefix) (v4, v6 bool) {
	return covers(prefixes, true), covers(prefixes, false)
}

// covers reports whether prefixes of one family cover that whole family.
func covers(prefixes []netip.Prefix, ipv4 bool) bool {
	type span struct{ lo, hi [16]byte }
	var spans []span
	for _, p := range prefixes {
		if p.Addr().Is4() != ipv4 {
			continue
		}
		lo, hi := bounds(p.Masked())
		spans = append(spans, span{lo, hi})
	}
	if len(spans) == 0 {
		return false
	}
	slices.SortFunc(spans, func(a, b span) int { return bytes.Compare(a.lo[:], b.lo[:]) })
	first, last := bounds(netip.PrefixFrom(familyZero(ipv4), 0))
	if spans[0].lo != first {
		return false
	}
	reach := spans[0].hi
	for _, s := range spans[1:] {
		if reach == last {
			break
		}
		next, overflow := increment(reach)
		if overflow || bytes.Compare(s.lo[:], next[:]) > 0 {
			return false // a gap
		}
		if bytes.Compare(s.hi[:], reach[:]) > 0 {
			reach = s.hi
		}
	}
	return reach == last
}

func familyZero(ipv4 bool) netip.Addr {
	if ipv4 {
		return netip.IPv4Unspecified()
	}
	return netip.IPv6Unspecified()
}

// bounds returns the first and last address of a masked prefix, as 16-byte
// values (IPv4 in the low four bytes).
func bounds(p netip.Prefix) (lo, hi [16]byte) {
	a := p.Addr()
	bits, offset := 128, 0
	if a.Is4() {
		bits, offset = 32, 12
		b := a.As4()
		copy(lo[12:], b[:])
	} else {
		lo = a.As16()
	}
	hi = lo
	for i := p.Bits(); i < bits; i++ {
		hi[offset+i/8] |= 0x80 >> (i % 8)
	}
	return lo, hi
}

func increment(v [16]byte) ([16]byte, bool) {
	for i := 15; i >= 0; i-- {
		v[i]++
		if v[i] != 0 {
			return v, false
		}
	}
	return v, true
}
