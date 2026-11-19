package tunnel

import (
	"fmt"
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

func TestRefuseEndpoint(t *testing.T) {
	prefixes := func(s ...string) []netip.Prefix {
		var p []netip.Prefix
		for _, x := range s {
			p = append(p, netip.MustParsePrefix(x))
		}
		return p
	}
	var slash8 []string
	for i := 0; i < 256; i++ {
		slash8 = append(slash8, fmt.Sprintf("%d.0.0.0/8", i))
	}
	const host = "vpn.example.org"
	for _, tc := range []struct {
		name    string
		host    string
		ep      string
		allowed []netip.Prefix
		want    bool
	}{
		{"private 10/8 in range", host, "10.98.0.1", prefixes("10.98.0.0/16"), true},
		{"private 172.16/12", host, "172.16.5.5", prefixes("172.16.0.0/12"), true},
		{"private 192.168/16", host, "192.168.1.5", prefixes("192.168.0.0/16"), true},
		{"CGNAT", host, "100.64.1.1", prefixes("100.64.0.0/10"), true},
		{"link-local v4", host, "169.254.1.1", prefixes("169.254.0.0/16"), true},
		{"unique-local v6", host, "fd00::1", prefixes("fd00::/64"), true},
		{"link-local v6", host, "fe80::1", prefixes("fe80::/10"), true},
		{"v4-mapped private", host, "::ffff:10.98.0.1", prefixes("10.98.0.0/16"), true},
		{"three /2 with a gap", host, "10.98.0.1", prefixes("0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2"), true},
		{"v4 full, v6 narrow, v6 endpoint", host, "fd00::1", prefixes("0.0.0.0/0", "fd00::/64"), true},

		{"public v4", host, "198.51.100.7", prefixes("198.51.100.0/24"), false},
		{"public v6", host, "2001:db8::1", prefixes("2001:db8::/32"), false},
		{"v4-mapped public", host, "::ffff:198.51.100.7", prefixes("198.51.100.0/24"), false},
		{"just above CGNAT", host, "100.128.0.1", prefixes("100.0.0.0/8"), false},
		{"private but outside routes", host, "192.168.1.5", prefixes("10.98.0.0/16"), false},
		{"v4 endpoint, v6 routes only", host, "10.98.0.1", prefixes("fd00::/64"), false},
		{"no routes", host, "10.98.0.1", nil, false},
		{"full v4 /0", host, "10.98.0.1", prefixes("0.0.0.0/0", "10.98.0.0/16"), false},
		{"full v4 /1 pair", host, "10.98.0.1", prefixes("0.0.0.0/1", "128.0.0.0/1", "10.98.0.0/16"), false},
		{"full v4 four /2", host, "10.98.0.1", prefixes("0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2", "10.98.0.0/16"), false},
		{"full v4 256 /8", host, "10.98.0.1", prefixes(append(slash8, "10.98.0.0/16")...), false},
		{"full v6 /0", host, "fd00::1", prefixes("::/0", "fd00::/64"), false},
		{"full v6 /1 pair", host, "fd00::1", prefixes("::/1", "8000::/1", "fd00::/64"), false},
		{"full v6 four /2", host, "fd00::1", prefixes("::/2", "4000::/2", "8000::/2", "c000::/2", "fd00::/64"), false},
		{"literal v4 host", "10.98.0.1", "10.98.0.1", prefixes("10.98.0.0/16"), false},
		{"literal v6 host", "fd00::1", "fd00::1", prefixes("fd00::/64"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := RefuseEndpoint(tc.host, netip.MustParseAddr(tc.ep), tc.allowed); got != tc.want {
				t.Fatalf("RefuseEndpoint(%s, %s) = %v", tc.host, tc.ep, got)
			}
		})
	}
}

func TestProbeTarget(t *testing.T) {
	for _, tc := range []struct {
		name    string
		address string
		allowed []string
		dns     []string
		want    string // "" for none
	}{
		{"DNS inside the routes", "10.98.10.4/32", []string{"10.98.0.0/16"}, []string{"10.98.0.1"}, "10.98.0.1:53"},
		{"second DNS inside", "10.98.10.4/32", []string{"10.98.0.0/16"}, []string{"192.0.2.53", "10.98.0.2"}, "10.98.0.2:53"},
		{"DNS outside: the first route", "10.98.10.4/32", []string{"10.20.0.0/16", "10.98.0.0/16"}, []string{"192.0.2.53"}, "10.20.0.1:53"},
		{"no DNS", "10.98.10.4/32", []string{"10.98.0.0/16"}, nil, "10.98.0.1:53"},
		{"a /32 route", "10.98.10.4/32", []string{"10.98.0.7/32"}, nil, "10.98.0.7:53"},
		{"IPv6 /128 route", "fd00::4/128", []string{"fd00::53/128"}, nil, "[fd00::53]:53"},
		{"/0 only", "10.98.10.4/32", []string{"0.0.0.0/0"}, nil, ""},
		{"/0 then a narrower route", "10.98.10.4/32", []string{"0.0.0.0/0", "10.98.0.0/16"}, nil, "10.98.0.1:53"},
		{"no address for the family", "10.98.10.4/32", []string{"fd00::/64"}, []string{"fd00::53"}, ""},
		{"IPv6 DNS with an IPv4 address", "10.98.10.4/32", []string{"10.98.0.0/16", "fd00::/64"}, []string{"fd00::53", "10.98.0.1"}, "10.98.0.1:53"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &protocol.Config{Version: 1, Address: tc.address,
				ServerPublicKey: "mkk2/n0976hg+yS1HkmS3Jr4EphDhzmX+vOZ02alXlY=", Endpoint: "vpn.example.com:51820",
				AllowedIPs: tc.allowed, DNS: protocol.DNS{Servers: tc.dns}}
			tcfg, err := c.Parse()
			if err != nil {
				t.Fatal(err)
			}
			got := ""
			if p := NewPlan(tcfg).Probe; p.IsValid() {
				got = p.String()
			}
			if got != tc.want {
				t.Fatalf("probe %q, want %q", got, tc.want)
			}
		})
	}
}

func TestProbeQuery(t *testing.T) {
	// A DNS query for the root's name servers: header, root name, NS, IN.
	want := []byte{0x48, 0x66, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1}
	if !reflect.DeepEqual(probeQuery[:], want) {
		t.Fatalf("%x", probeQuery)
	}
}
