package tunnel

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/protocol"
)

func cfg(t *testing.T, allowed []string, dns []string, search []string) *protocol.TunnelConfig {
	t.Helper()
	c := &protocol.Config{Version: 1, Address: "10.98.10.4/32",
		ServerPublicKey: "mkk2/n0976hg+yS1HkmS3Jr4EphDhzmX+vOZ02alXlY=", Endpoint: "vpn.example.com:51820",
		AllowedIPs: allowed, DNS: protocol.DNS{Servers: dns, Search: search}}
	tc, err := c.Parse()
	if err != nil {
		t.Fatal(err)
	}
	return tc
}

func TestSplitTunnelPlan(t *testing.T) {
	p := NewPlan(cfg(t, []string{"10.98.0.0/16", "fd00::/64", "10.98.0.0/16"}, []string{"10.98.0.1"}, []string{"corp", "Example.Internal"}))
	if len(p.Routes4) != 1 || len(p.Routes6) != 1 || p.Full4 || p.Full6 {
		t.Fatalf("routes %+v", p)
	}
	servers := []netip.Addr{netip.MustParseAddr("10.98.0.1")}
	// All names go to the server's DNS while connected, as with the
	// WireGuard app's "DNS =": it may answer names outside its zone.
	if !reflect.DeepEqual(p.InterfaceDNS, servers) {
		t.Fatalf("interface DNS %v", p.InterfaceDNS)
	}
	want := &Rule{Namespaces: []string{"."}, Servers: servers}
	if !reflect.DeepEqual(p.Rule, want) {
		t.Fatalf("rule %+v", p.Rule)
	}
	if !reflect.DeepEqual(p.SearchDomains, []string{"corp", "example.internal"}) {
		t.Fatalf("search domains %v", p.SearchDomains)
	}
	if len(p.DNSOutsideTunnel) != 0 {
		t.Fatalf("DNS outside tunnel %v", p.DNSOutsideTunnel)
	}
	if p.MTU != protocol.DefaultMTU {
		t.Fatalf("MTU %d", p.MTU)
	}
}

func TestSplitTunnelNoSearchPlan(t *testing.T) {
	p := NewPlan(cfg(t, []string{"10.98.0.0/16"}, []string{"10.98.0.1"}, nil))
	servers := []netip.Addr{netip.MustParseAddr("10.98.0.1")}
	if !reflect.DeepEqual(p.InterfaceDNS, servers) {
		t.Fatalf("interface DNS %v", p.InterfaceDNS)
	}
	want := &Rule{Namespaces: []string{"."}, Servers: servers}
	if !reflect.DeepEqual(p.Rule, want) {
		t.Fatalf("rule %+v", p.Rule)
	}
	if len(p.SearchDomains) != 0 {
		t.Fatalf("search domains %v", p.SearchDomains)
	}
}

func TestFullTunnelPlan(t *testing.T) {
	p := NewPlan(cfg(t, []string{"0.0.0.0/1", "128.0.0.0/1"}, []string{"10.98.0.1"}, []string{"corp"}))
	if !p.Full4 || p.Full6 || len(p.InterfaceDNS) != 1 || p.Rule == nil || p.Rule.Namespaces[0] != "." {
		t.Fatalf("%+v %+v", p, p.Rule)
	}
	if !reflect.DeepEqual(p.SearchDomains, []string{"corp"}) {
		t.Fatalf("search domains %v", p.SearchDomains)
	}
}

func TestNoDNSPlan(t *testing.T) {
	p := NewPlan(cfg(t, []string{"10.98.0.0/16"}, nil, nil))
	if p.Rule != nil || len(p.InterfaceDNS) != 0 || len(p.DNSOutsideTunnel) != 0 {
		t.Fatalf("%+v", p)
	}
}

func TestDNSOutsideTunnel(t *testing.T) {
	addrs := func(s ...string) []netip.Addr {
		var a []netip.Addr
		for _, x := range s {
			a = append(a, netip.MustParseAddr(x))
		}
		return a
	}
	for _, tc := range []struct {
		name    string
		allowed []string
		dns     []string
		want    []netip.Addr
	}{
		{"outside", []string{"10.98.0.0/16"}, []string{"192.0.2.53"}, addrs("192.0.2.53")},
		{"inside", []string{"10.98.0.0/16"}, []string{"10.98.0.1"}, nil},
		{"full tunnel", []string{"0.0.0.0/1", "128.0.0.0/1"}, []string{"192.0.2.53"}, nil},
		{"IPv6 with IPv4 routes", []string{"10.98.0.0/16"}, []string{"10.98.0.1", "fd00::53"}, addrs("fd00::53")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := NewPlan(cfg(t, tc.allowed, tc.dns, nil))
			if !reflect.DeepEqual(p.DNSOutsideTunnel, tc.want) {
				t.Fatalf("DNS outside tunnel %v, want %v", p.DNSOutsideTunnel, tc.want)
			}
			// Still applied: the rule points at every server.
			if p.Rule == nil || !reflect.DeepEqual(p.Rule.Servers, addrs(tc.dns...)) {
				t.Fatalf("rule %+v", p.Rule)
			}
		})
	}
}

func TestEndpointInside(t *testing.T) {
	prefixes := func(s ...string) []netip.Prefix {
		var p []netip.Prefix
		for _, x := range s {
			p = append(p, netip.MustParsePrefix(x))
		}
		return p
	}
	for _, tc := range []struct {
		name    string
		ep      string
		allowed []netip.Prefix
		want    bool
	}{
		{"IPv4 inside", "10.98.0.1", prefixes("10.98.0.0/16"), true},
		{"IPv4 outside", "192.0.2.10", prefixes("10.98.0.0/16", "fd00::/64"), false},
		{"IPv6 inside", "fd00::1", prefixes("10.98.0.0/16", "fd00::/64"), true},
		{"IPv6 outside", "2001:db8::1", prefixes("fd00::/64"), false},
		{"IPv4-mapped inside", "::ffff:10.98.0.1", prefixes("10.98.0.0/16"), true},
		{"IPv4-mapped outside", "::ffff:192.0.2.10", prefixes("10.98.0.0/16"), false},
		{"no routes", "10.98.0.1", nil, false},
		{"full tunnel, public address", "192.0.2.10", prefixes("0.0.0.0/0"), false},
		{"full tunnel as /1 pair, public address", "192.0.2.10", prefixes("0.0.0.0/1", "128.0.0.0/1"), false},
		{"full tunnel and a range, inside the range", "10.98.0.1", prefixes("0.0.0.0/0", "10.98.0.0/16"), true},
		{"/1 pair and a range, inside the range", "10.98.0.1", prefixes("0.0.0.0/1", "128.0.0.0/1", "10.98.0.0/16"), true},
		{"full IPv6 tunnel, public address", "2001:db8::1", prefixes("::/0"), false},
		{"IPv6 /1 pair, public address", "2001:db8::1", prefixes("::/1", "8000::/1"), false},
		{"full IPv6 tunnel and a range, inside the range", "fd00::1", prefixes("::/0", "fd00::/64"), true},
		{"IPv6 /1 pair and a range, inside the range", "fd00::1", prefixes("::/1", "8000::/1", "fd00::/64"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := EndpointInside(netip.MustParseAddr(tc.ep), tc.allowed); got != tc.want {
				t.Fatalf("EndpointInside(%s, %v) = %v", tc.ep, tc.allowed, got)
			}
		})
	}
}
