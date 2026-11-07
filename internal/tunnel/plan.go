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
	// DNS on the tunnel interface itself. Set only for a full tunnel; for a
	// split tunnel the interface has no DNS servers, so Windows keeps using
	// the user's own for everything else.
	InterfaceDNS []netip.Addr
	// Search domains on the tunnel interface, so short names resolve.
	SearchDomains []string
	// Name resolution rule (NRPT): names under Namespaces are resolved by
	// Servers. For a split tunnel these are the search domains; for a full
	// tunnel the root ("."), so no name is sent elsewhere.
	Rule *Rule
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
	switch {
	case p.Full4 || p.Full6:
		p.InterfaceDNS = servers
		p.Rule = &Rule{Namespaces: []string{"."}, Servers: servers}
	case len(cfg.SearchDomains) > 0:
		rule := &Rule{Servers: servers}
		for _, d := range cfg.SearchDomains {
			rule.Namespaces = append(rule.Namespaces, "."+d)
		}
		p.Rule = rule
	}
	return p
}
