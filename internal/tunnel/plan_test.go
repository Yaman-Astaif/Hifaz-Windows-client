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
	if len(p.InterfaceDNS) != 0 {
		t.Fatal("split tunnel must not set DNS servers on the interface")
	}
	want := &Rule{Namespaces: []string{".corp", ".example.internal"}, Servers: []netip.Addr{netip.MustParseAddr("10.98.0.1")}}
	if !reflect.DeepEqual(p.Rule, want) {
		t.Fatalf("rule %+v", p.Rule)
	}
	if p.MTU != protocol.DefaultMTU {
		t.Fatalf("MTU %d", p.MTU)
	}
}

func TestFullTunnelPlan(t *testing.T) {
	p := NewPlan(cfg(t, []string{"0.0.0.0/1", "128.0.0.0/1"}, []string{"10.98.0.1"}, []string{"corp"}))
	if !p.Full4 || p.Full6 || len(p.InterfaceDNS) != 1 || p.Rule == nil || p.Rule.Namespaces[0] != "." {
		t.Fatalf("%+v %+v", p, p.Rule)
	}
}

func TestNoDNSPlan(t *testing.T) {
	p := NewPlan(cfg(t, []string{"10.98.0.0/16"}, nil, nil))
	if p.Rule != nil || len(p.InterfaceDNS) != 0 {
		t.Fatalf("%+v", p)
	}
	// DNS servers but no search domains: nothing to route names to.
	p = NewPlan(cfg(t, []string{"10.98.0.0/16"}, []string{"10.98.0.1"}, nil))
	if p.Rule != nil || len(p.InterfaceDNS) != 0 {
		t.Fatalf("%+v", p)
	}
}
