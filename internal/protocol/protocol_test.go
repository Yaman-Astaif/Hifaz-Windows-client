package protocol

import (
	"crypto/rand"
	"strings"
	"testing"
)

func TestNormalizeServerURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://vpn.example.com":          "https://vpn.example.com",
		"https://VPN.Example.com/":         "https://vpn.example.com",
		"HTTPS://vpn.example.com:443/":     "https://vpn.example.com",
		"https://vpn.example.com:8443":     "https://vpn.example.com:8443",
		" https://example.com/vpn/ ":       "https://example.com/vpn",
		"https://[2001:db8::1]:443/hifaz/": "https://[2001:db8::1]/hifaz",
	} {
		got, err := NormalizeServerURL(in)
		if err != nil || got != want {
			t.Errorf("%q: %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{
		"http://vpn.example.com", "vpn.example.com", "https://", "https://user@vpn.example.com",
		"https://vpn.example.com/?a=1", "https://vpn.example.com/#x", "ftp://vpn.example.com", "",
	} {
		if got, err := NormalizeServerURL(bad); err == nil {
			t.Errorf("%q accepted as %q", bad, got)
		}
	}
}

const testFP = "Y8wKPoS95ovsvxPa4wePDKKz-c2ZlrHJ_BdPS7aC52Q"

func TestParseEnrollLink(t *testing.T) {
	token := strings.Repeat("A", 43)
	l, err := ParseEnrollLink("https://VPN.example.com/login/enroll#" + token + "." + testFP)
	if err != nil {
		t.Fatal(err)
	}
	if l.Server != "https://vpn.example.com" || l.Token != token || l.Fingerprint != testFP {
		t.Fatalf("%+v", l)
	}
	l, err = ParseEnrollLink("https://example.com/vpn/login/enroll/#" + token)
	if err != nil || l.Server != "https://example.com/vpn" || l.Fingerprint != "" {
		t.Fatalf("old link: %+v, %v", l, err)
	}
	for _, bad := range []string{
		"https://vpn.example.com/login/enroll",                             // no token
		"https://vpn.example.com/login#" + token,                           // wrong path
		"http://vpn.example.com/login/enroll#" + token,                     // not https
		"https://vpn.example.com/login/enroll#" + token + ".short",         // bad fingerprint
		"https://vpn.example.com/login/enroll#to ken",                      // bad token
		"https://vpn.example.com/login/enroll#" + strings.Repeat("A", 200), // too long
		"https://vpn.example.com/login/enroll?x=1#" + token,                // query
	} {
		if l, err := ParseEnrollLink(bad); err == nil {
			t.Errorf("%q accepted: %+v", bad, l)
		}
	}
}

func goodConfig() *Config {
	return &Config{
		Version: 7, Address: "10.98.10.4/32",
		ServerPublicKey: "mkk2/n0976hg+yS1HkmS3Jr4EphDhzmX+vOZ02alXlY=",
		Endpoint:        "vpn.example.com:51820",
		AllowedIPs:      []string{"10.98.0.0/16", "10.20.0.0/16", "fd00::/64"},
		DNS:             DNS{Servers: []string{"10.98.0.1"}, Search: []string{"Corp.", "example.internal"}},
		MTU:             1420,
	}
}

func TestConfigParse(t *testing.T) {
	tc, err := goodConfig().Parse()
	if err != nil {
		t.Fatal(err)
	}
	if tc.EndpointHost != "vpn.example.com" || tc.EndpointPort != 51820 || len(tc.AllowedIPs) != 3 ||
		tc.SearchDomains[0] != "corp" || tc.MTU != 1420 {
		t.Fatalf("%+v", tc)
	}
	c := goodConfig()
	c.MTU = 0
	if tc, err := c.Parse(); err != nil || tc.MTU != DefaultMTU {
		t.Fatalf("default MTU: %v %v", tc, err)
	}
	c = goodConfig()
	c.Endpoint = "[2001:db8::1]:51820"
	if tc, err := c.Parse(); err != nil || tc.EndpointHost != "2001:db8::1" {
		t.Fatalf("IPv6 endpoint: %v %v", tc, err)
	}

	for name, change := range map[string]func(*Config){
		"no version":          func(c *Config) { c.Version = 0 },
		"bad address":         func(c *Config) { c.Address = "10.98.10.4" },
		"zero prefix address": func(c *Config) { c.Address = "0.0.0.0/0" },
		"bad key":             func(c *Config) { c.ServerPublicKey = "abc" },
		"zero key":            func(c *Config) { c.ServerPublicKey = Key{}.String() },
		"no port":             func(c *Config) { c.Endpoint = "vpn.example.com" },
		"port 0":              func(c *Config) { c.Endpoint = "vpn.example.com:0" },
		"bad host":            func(c *Config) { c.Endpoint = "vpn_example.com:51820" },
		"loopback endpoint":   func(c *Config) { c.Endpoint = "127.0.0.1:51820" },
		"no allowed IPs":      func(c *Config) { c.AllowedIPs = nil },
		"non-canonical range": func(c *Config) { c.AllowedIPs = []string{"10.98.1.0/16"} },
		"too many ranges":     func(c *Config) { c.AllowedIPs = make([]string, MaxAllowedIPs+1) },
		"bad DNS server":      func(c *Config) { c.DNS.Servers = []string{"10.98.0.1%eth0"} },
		"root search domain":  func(c *Config) { c.DNS.Search = []string{"."} },
		"bad search domain":   func(c *Config) { c.DNS.Search = []string{"-corp"} },
		"search without DNS":  func(c *Config) { c.DNS.Servers = nil },
		"MTU too small":       func(c *Config) { c.MTU = 576 },
		"MTU too large":       func(c *Config) { c.MTU = 65535 },
	} {
		c := goodConfig()
		change(c)
		if _, err := c.Parse(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	var nilConfig *Config
	if _, err := nilConfig.Parse(); err == nil {
		t.Error("nil config accepted")
	}
}

func TestSealRoundTrip(t *testing.T) {
	priv, pub, err := GenerateWireGuardKey()
	if err != nil {
		t.Fatal(err)
	}
	var psk Key
	rand.Read(psk[:])
	sealed, err := SealPSK(psk, pub, "d_1", rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenSealedPSK(sealed, priv, "d_1")
	if err != nil || got != psk {
		t.Fatalf("round trip: %v", err)
	}
	if _, err := OpenSealedPSK(sealed[:len(sealed)-4], priv, "d_1"); err != ErrSealedPSK {
		t.Fatalf("short input: %v", err)
	}
	// A low-order ephemeral key (all zeros) gives an all-zero shared secret.
	zero := make([]byte, sealedLen)
	if _, err := OpenSealedPSK(b64.EncodeToString(zero), priv, "d_1"); err != ErrSealedPSK {
		t.Fatalf("low-order point: %v", err)
	}
}

func TestNonceAndFingerprintStrict(t *testing.T) {
	n, err := NewNonce()
	if err != nil || !ValidNonce(n) {
		t.Fatalf("%q %v", n, err)
	}
	// Non-canonical encodings (extra bits in the last character) are refused.
	if ValidNonce("AAECAwQFBgcICQoLDA0ODx") || ValidNonce("short") || ValidNonce(n+"A") {
		t.Fatal("bad nonce accepted")
	}
	if _, err := ParseFingerprint(testFP[:42] + "R"); err == nil {
		t.Fatal("non-canonical fingerprint accepted")
	}
}
