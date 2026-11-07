package policy

import (
	"net/netip"
	"testing"

	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/protocol"
)

func prefixes(t *testing.T, s ...string) []netip.Prefix {
	t.Helper()
	var out []netip.Prefix
	for _, x := range s {
		out = append(out, netip.MustParsePrefix(x))
	}
	return out
}

func TestFullTunnel(t *testing.T) {
	for _, c := range []struct {
		ranges []string
		v4, v6 bool
	}{
		{[]string{"10.98.0.0/16", "10.20.0.0/16"}, false, false},
		{[]string{"0.0.0.0/0"}, true, false},
		{[]string{"::/0"}, false, true},
		{[]string{"0.0.0.0/1", "128.0.0.0/1"}, true, false},
		{[]string{"128.0.0.0/1", "0.0.0.0/1", "10.0.0.0/8"}, true, false},
		{[]string{"0.0.0.0/1"}, false, false},
		{[]string{"0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/3", "224.0.0.0/3"}, true, false},
		{[]string{"0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "224.0.0.0/3"}, false, false}, // 192/3 missing
		{[]string{"::/1", "8000::/1", "0.0.0.0/0"}, true, true},
		{[]string{"255.255.255.255/32"}, false, false},
		{[]string{"::/1", "8000::/2"}, false, false},
	} {
		v4, v6 := FullTunnel(prefixes(t, c.ranges...))
		if v4 != c.v4 || v6 != c.v6 {
			t.Errorf("%v: got %v %v, want %v %v", c.ranges, v4, v6, c.v4, c.v6)
		}
	}
}

// complement returns the prefixes that, with p, exactly cover p's family.
func complement(p netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	b := p.Addr().As16()
	for i := 0; i < p.Bits(); i++ {
		s := b
		s[i/8] ^= 0x80 >> (i % 8)
		out = append(out, netip.PrefixFrom(netip.AddrFrom16(s), i+1).Masked())
	}
	return out
}

func TestFullTunnelAroundMappedRange(t *testing.T) {
	mapped := netip.MustParsePrefix("::ffff:0.0.0.0/96")
	rest := complement(mapped)
	if _, v6 := FullTunnel(append(rest, mapped)); !v6 {
		t.Fatal("IPv6 cover that includes the IPv4-mapped range not detected")
	}
	if _, v6 := FullTunnel(rest); v6 {
		t.Fatal("cover with a gap reported as full")
	}
}

func TestCheckConfig(t *testing.T) {
	full := &protocol.TunnelConfig{AllowedIPs: prefixes(t, "0.0.0.0/1", "128.0.0.0/1")}
	split := &protocol.TunnelConfig{AllowedIPs: prefixes(t, "10.98.0.0/16")}
	if err := (Policy{}).CheckConfig(full); err != ErrFullTunnel {
		t.Fatalf("default policy allowed a full tunnel: %v", err)
	}
	if err := (Policy{}).CheckConfig(split); err != nil {
		t.Fatal(err)
	}
	if err := (Policy{AllowFullTunnel: true}).CheckConfig(full); err != nil {
		t.Fatal(err)
	}
}

func TestServers(t *testing.T) {
	const fp = protocol.Fingerprint("Y8wKPoS95ovsvxPa4wePDKKz-c2ZlrHJ_BdPS7aC52Q")
	a, err := ParseServer("https://VPN.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseServer("https://other.example.com " + string(fp))
	if err != nil {
		t.Fatal(err)
	}
	p := Policy{Servers: []Server{a, b}}
	if p.AllowsServer("https://vpn.example.com", "anything") != nil {
		t.Error("listed server without fingerprint refused")
	}
	if p.AllowsServer("https://other.example.com", fp) != nil {
		t.Error("listed server with its fingerprint refused")
	}
	if p.AllowsServer("https://other.example.com", "different") != ErrServerNotAllowed {
		t.Error("wrong fingerprint allowed")
	}
	if p.AllowsServer("https://evil.example.com", fp) != ErrServerNotAllowed {
		t.Error("unlisted server allowed")
	}
	if (Policy{}).AllowsServer("https://evil.example.com", fp) != nil {
		t.Error("empty list must allow any server")
	}
	for _, bad := range []string{"", "http://x.example.com", "https://x.example.com short", "a b c"} {
		if _, err := ParseServer(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
