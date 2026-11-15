package tunnel

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/protocol"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/third_party/wireguard-windows/driver"
)

// TestTunnelUpDown creates a real WireGuardNT adapter. It needs
// administrator rights and wireguard.dll next to the test program, so it
// runs only when HIFAZ_TUNNEL_TEST=1 (the Windows CI job sets it).
func TestTunnelUpDown(t *testing.T) {
	if os.Getenv("HIFAZ_TUNNEL_TEST") != "1" {
		t.Skip("set HIFAZ_TUNNEL_TEST=1 (administrator, wireguard.dll present)")
	}
	_, peer, _ := protocol.GenerateWireGuardKey()
	priv, _, _ := protocol.GenerateWireGuardKey()
	c := &protocol.Config{Version: 1, Address: "10.255.10.4/32", ServerPublicKey: peer.String(),
		Endpoint:   "192.0.2.1:51820", // TEST-NET-1: never answers
		AllowedIPs: []string{"10.255.0.0/16"},
		DNS:        protocol.DNS{Servers: []string{"10.255.0.1"}, Search: []string{"hifaz-test.invalid"}}}
	cfg, err := c.Parse()
	if err != nil {
		t.Fatal(err)
	}
	tun := New(func(msg string, args ...any) { t.Log(append([]any{msg}, args...)...) })
	if err := tun.Up(cfg, priv, protocol.Key{1}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tun.Down() })

	if _, err := driver.OpenAdapter(AdapterName); err != nil {
		t.Fatalf("adapter not found: %v", err)
	}
	// DNS waits for the server's answer: nothing until SetDNS.
	noRule := func(when string) {
		t.Helper()
		if _, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptLocal+`\`+nrptRuleKey, registry.QUERY_VALUE); !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			t.Fatalf("%s: DNS rule present: %v", when, err)
		}
	}
	noRule("after Up")
	// The probe goes to the DNS server inside the routes; nothing answers.
	if err := tun.Probe(); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if err := tun.SetDNS(true); err != nil {
		t.Fatal(err)
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptLocal+`\`+nrptRuleKey, registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("DNS rule not written: %v", err)
	}
	names, _, _ := k.GetStringsValue("Name")
	servers, _, _ := k.GetStringValue("GenericDNSServers")
	k.Close()
	// All names go to the tunnel's DNS while connected.
	if len(names) != 1 || names[0] != "." {
		t.Fatalf("DNS rule names %v", names)
	}
	if servers != "10.255.0.1" {
		t.Fatalf("DNS rule servers %q", servers)
	}
	if _, err := tun.Stats(); err != nil {
		t.Fatal(err)
	}

	// A newer configuration with another route.
	c.Version, c.AllowedIPs = 2, []string{"10.255.0.0/16", "10.254.0.0/16"}
	cfg2, _ := c.Parse()
	if err := tun.Reconfigure(cfg2); err != nil {
		t.Fatal(err)
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptLocal+`\`+nrptRuleKey, registry.QUERY_VALUE); err != nil {
		t.Fatalf("DNS rule lost by Reconfigure: %v", err)
	} else {
		k.Close()
	}

	// A configuration without DNS servers removes the rule; the next one
	// with DNS brings it back.
	noDNS := *c
	noDNS.Version, noDNS.DNS = 3, protocol.DNS{}
	cfg3, err := noDNS.Parse()
	if err != nil {
		t.Fatal(err)
	}
	if err := tun.Reconfigure(cfg3); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptLocal+`\`+nrptRuleKey, registry.QUERY_VALUE); !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		t.Fatalf("DNS rule kept without DNS servers: %v", err)
	}
	if err := tun.Reconfigure(cfg2); err != nil {
		t.Fatal(err)
	}

	// The server stops answering: DNS goes, and a newer configuration
	// does not bring it back.
	if err := tun.SetDNS(false); err != nil {
		t.Fatal(err)
	}
	noRule("after SetDNS(false)")
	c.Version = 4
	cfg4, _ := c.Parse()
	if err := tun.Reconfigure(cfg4); err != nil {
		t.Fatal(err)
	}
	noRule("Reconfigure with DNS off")
	if err := tun.SetDNS(true); err != nil {
		t.Fatal(err)
	}

	checkPeer := func(when string) {
		conf, err := tun.adapter.Configuration()
		if err != nil || conf.PeerCount != 1 {
			t.Fatalf("%s: configuration %v, %d peers", when, err, conf.PeerCount)
		}
		p := conf.FirstPeer()
		// Idle detection on the server depends on silence: never a keepalive.
		// (Read back, the driver marks the field as present; its value is
		// what matters: 0 means off.)
		if p.PersistentKeepalive != 0 {
			t.Fatalf("%s: persistent keepalive set (%d)", when, p.PersistentKeepalive)
		}
		if p.LastHandshake != 0 {
			t.Fatalf("%s: the peer carries an earlier handshake", when)
		}
	}
	checkPeer("first sign-in")

	// The next sign-in gets a new adapter with a fresh peer: no session keys
	// from before, so the first packet starts a new handshake at once.
	if err := tun.Down(); err != nil {
		t.Fatal(err)
	}
	if err := tun.Up(cfg2, priv, protocol.Key{2}); err != nil {
		t.Fatal(err)
	}
	checkPeer("next sign-in")

	if err := tun.Down(); err != nil {
		t.Fatal(err)
	}
	if _, err := driver.OpenAdapter(AdapterName); err == nil {
		t.Fatal("adapter left behind")
	}
	if _, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptLocal+`\`+nrptRuleKey, registry.QUERY_VALUE); !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		t.Fatalf("DNS rule left behind: %v", err)
	}
}
