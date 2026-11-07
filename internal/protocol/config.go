package protocol

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Config is the tunnel configuration as the server sends it (section 9).
type Config struct {
	Version         int64    `json:"version"`
	Address         string   `json:"address"`
	ServerPublicKey string   `json:"server_public_key"`
	Endpoint        string   `json:"endpoint"`
	AllowedIPs      []string `json:"allowed_ips"`
	DNS             DNS      `json:"dns"`
	MTU             int      `json:"mtu"`
}

// DNS holds the tunnel's name servers and search domains.
type DNS struct {
	Servers []string `json:"servers"`
	Search  []string `json:"search"`
}

// Limits on a tunnel configuration. They are far above what a Hifaz group
// needs and only stop a broken or hostile answer from doing harm.
const (
	MaxAllowedIPs    = 1024
	MaxDNSServers    = 8
	MaxSearchDomains = 32
	DefaultMTU       = 1420
	MinMTU           = 1280 // the IPv6 minimum
	MaxMTU           = 9000
)

// TunnelConfig is a checked configuration, ready to apply.
type TunnelConfig struct {
	Version         int64
	Address         netip.Prefix
	ServerPublicKey Key
	EndpointHost    string // host name or IP address
	EndpointPort    uint16
	AllowedIPs      []netip.Prefix
	DNSServers      []netip.Addr
	SearchDomains   []string // lower case, no trailing dot
	MTU             int
}

// Parse checks every field and returns the configuration in typed form.
func (c *Config) Parse() (*TunnelConfig, error) {
	if c == nil {
		return nil, errors.New("no tunnel configuration")
	}
	t := &TunnelConfig{Version: c.Version, MTU: c.MTU}
	var err error
	if c.Version < 1 {
		return nil, errors.New("tunnel configuration has no version")
	}
	if t.Address, err = netip.ParsePrefix(c.Address); err != nil || t.Address.Bits() == 0 ||
		!usableUnicast(t.Address.Addr()) {
		return nil, fmt.Errorf("invalid tunnel address %q", c.Address)
	}
	if t.ServerPublicKey, err = ParseKey(c.ServerPublicKey); err != nil || t.ServerPublicKey.IsZero() {
		return nil, errors.New("invalid server public key")
	}
	if t.EndpointHost, t.EndpointPort, err = parseEndpoint(c.Endpoint); err != nil {
		return nil, err
	}
	if len(c.AllowedIPs) == 0 || len(c.AllowedIPs) > MaxAllowedIPs {
		return nil, errors.New("invalid number of allowed IP ranges")
	}
	for _, s := range c.AllowedIPs {
		p, err := netip.ParsePrefix(s)
		if err != nil || p != p.Masked() {
			return nil, fmt.Errorf("invalid allowed IP range %q", s)
		}
		t.AllowedIPs = append(t.AllowedIPs, p)
	}
	if len(c.DNS.Servers) > MaxDNSServers {
		return nil, errors.New("too many DNS servers")
	}
	for _, s := range c.DNS.Servers {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" || !usableUnicast(a) {
			return nil, fmt.Errorf("invalid DNS server %q", s)
		}
		t.DNSServers = append(t.DNSServers, a.Unmap())
	}
	if len(c.DNS.Search) > MaxSearchDomains {
		return nil, errors.New("too many search domains")
	}
	if len(c.DNS.Search) > 0 && len(t.DNSServers) == 0 {
		return nil, errors.New("search domains without DNS servers")
	}
	for _, s := range c.DNS.Search {
		d, ok := normalizeDomain(s)
		if !ok {
			return nil, fmt.Errorf("invalid search domain %q", s)
		}
		t.SearchDomains = append(t.SearchDomains, d)
	}
	if t.MTU == 0 {
		t.MTU = DefaultMTU
	}
	if t.MTU < MinMTU || t.MTU > MaxMTU {
		return nil, fmt.Errorf("invalid MTU %d", c.MTU)
	}
	return t, nil
}

func usableUnicast(a netip.Addr) bool {
	return a.IsValid() && !a.IsUnspecified() && !a.IsMulticast() && !a.IsLoopback()
}

func parseEndpoint(s string) (string, uint16, error) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, fmt.Errorf("invalid endpoint %q", s)
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return "", 0, fmt.Errorf("invalid endpoint port %q", port)
	}
	if a, err := netip.ParseAddr(host); err == nil {
		if a.Zone() != "" || !usableUnicast(a) {
			return "", 0, fmt.Errorf("invalid endpoint address %q", host)
		}
		return a.Unmap().String(), uint16(p), nil
	}
	h, ok := normalizeDomain(host)
	if !ok {
		return "", 0, fmt.Errorf("invalid endpoint host %q", host)
	}
	return h, uint16(p), nil
}

// normalizeDomain checks a DNS name (letters, digits and hyphens; labels of
// 1–63 characters; at most 253 in all) and returns it in lower case without
// a trailing dot. Single labels ("corp") are fine; the root (".") is refused,
// since as a search domain it would send every query to the tunnel.
func normalizeDomain(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	if s == "" || len(s) > 253 {
		return "", false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", false
			}
		}
	}
	return s, true
}
