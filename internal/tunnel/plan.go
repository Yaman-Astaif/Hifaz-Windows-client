// Package tunnel brings the Hifaz tunnel up and down on Windows: the
// WireGuardNT adapter (through the official wireguard.dll), its address,
// routes and MTU, and DNS. The decisions — what goes where — are made in
// this file, without Windows calls, so they are tested on any system; the
// Windows side applies them.
package tunnel

import (
	"net/netip"
	"slices"

	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/policy"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/protocol"
)

// Plan is what Up and Reconfigure apply.
type Plan struct {
	Address netip.Prefix
	Routes4 []netip.Prefix // through the tunnel, IPv4
	Routes6 []netip.Prefix // through the tunnel, IPv6
	MTU     int
	// Full4/Full6: all traffic of that family goes through the tunnel (only
	// when the policy allows it).
	Full4, Full6 bool
	// DNS on the tunnel interface: the server's DNS servers, for split and
	// full tunnels alike. While connected, every name goes to them, as with
	// the WireGuard app's "DNS =" line: the server's DNS may give a private
	// answer for a name outside its own zone (and in Hifaz's strict DNS
	// mode it is the only DNS the user may use). Routes stay as the server
	// sent them; only DNS is sent to the tunnel.
	InterfaceDNS []netip.Addr
	// Search domains on the tunnel interface, so short names resolve.
	SearchDomains []string
	// Name resolution rule (NRPT): names under Namespaces are resolved by
	// Servers. Always the root ("."), so no name is sent elsewhere while
	// connected; removed again when the tunnel goes down.
	Rule *Rule
	// DNS servers not inside any of the tunnel's routes: queries to them
	// leave by the normal network. Applied anyway (as WireGuard does), but
	// worth a line in the log.
	DNSOutsideTunnel []netip.Addr
}

// Rule is one NRPT rule.
type Rule struct {
	Namespaces []string // ".corp" style suffixes, or "." for all names
	Servers    []netip.Addr
}

// NewPlan derives the plan from a checked configuration.
func NewPlan(cfg *protocol.TunnelConfig) *Plan {
	p := &Plan{Address: cfg.Address, MTU: cfg.MTU, SearchDomains: slices.Clone(cfg.SearchDomains)}
	seen := map[netip.Prefix]bool{}
	for _, r := range cfg.AllowedIPs {
		r = r.Masked()
		if seen[r] {
			continue
		}
		seen[r] = true
		if r.Addr().Is4() {
			p.Routes4 = append(p.Routes4, r)
		} else {
			p.Routes6 = append(p.Routes6, r)
		}
	}
	p.Full4, p.Full6 = policy.FullTunnel(cfg.AllowedIPs)
	if len(cfg.DNSServers) == 0 {
		return p
	}
	servers := slices.Clone(cfg.DNSServers)
	p.InterfaceDNS = servers
	p.Rule = &Rule{Namespaces: []string{"."}, Servers: servers}
	for _, a := range servers {
		if !slices.ContainsFunc(cfg.AllowedIPs, func(r netip.Prefix) bool { return r.Contains(a) }) {
			p.DNSOutsideTunnel = append(p.DNSOutsideTunnel, a)
		}
	}
	return p
}

// cgnat is the shared address space (RFC 6598), used for private networks.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// nonPublic reports whether a is a private, CGNAT, unique-local or
// link-local address. Everything else counts as public.
func nonPublic(a netip.Addr) bool {
	if a.Is4() {
		return a.IsPrivate() || cgnat.Contains(a) || a.IsLinkLocalUnicast()
	}
	return a.IsPrivate() || a.IsLinkLocalUnicast()
}

// RefuseEndpoint reports whether Reconfigure should keep the current
// endpoint instead of ep, which a lookup of host returned.
//
// The driver never sends the tunnel's encrypted packets into its own
// interface, so an endpoint reachable only through the tunnel would stop the
// tunnel working. The server's DNS answers every lookup while connected. An
// answer that is a private, CGNAT, unique-local or link-local address inside
// the narrower routes is assumed to be a private answer from the server's
// DNS, reachable only through the tunnel, and is refused. Not refused: a
// literal address (no lookup was made), a public address, and any address
// when the routes cover its whole family (a full tunnel, however split),
// where the driver reaches the endpoint by skipping its own interface.
func RefuseEndpoint(host string, ep netip.Addr, allowed []netip.Prefix) bool {
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	ep = ep.Unmap()
	if !nonPublic(ep) {
		return false
	}
	v4, v6 := policy.FullTunnel(allowed)
	if (ep.Is4() && v4) || (ep.Is6() && v6) {
		return false
	}
	return slices.ContainsFunc(allowed, func(r netip.Prefix) bool { return r.Contains(ep) })
}
